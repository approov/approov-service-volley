# Advanced Options

The `approov-service-volley` package works through the HTTP stack that you get from `ApproovService`. After you call `initialize` with your account ID, the package adds an Approov token to each request to your API domains. This applies to requests that go through a `RequestQueue` built with that stack. The token is a signed JWT that provides proof of attestation, which your backend can check.

A standard integration of the Approov Package for Volley needs nothing from this document. You add the dependency, initialize, and build your queue with the stack, as the [README](README.md) shows. The options below change the defaults, suitable for applications with specific needs. You can find every method used in this document in [REFERENCE.md](REFERENCE.md).

| What you need | Read |
| :--- | :--- |
| Understand what reaches your backend | [What each request carries](#what-each-request-carries), then [What happens by default](#what-happens-by-default) |
| Change how network failures are handled | [What happens by default](#what-happens-by-default), then [Service mutators](#service-mutators) |
| Protect request contents with signatures | [Message signing](#message-signing), then [Account Message Signing](https://docs.approov.io/operations/message-signing/account/) |
| Replace an embedded API secret | [Secure strings](#secure-strings) |
| Configure startup or runtime activation | [Initialize, then configure](#initialize-then-configure), then [Bypass initialization](#bypass-initialization) |
| Understand redirects, retries and connections | [Redirects](#redirects), [Retries and held requests](#retries-and-held-requests), then [Connection validation](#connection-validation) |
| Investigate an unexpected result | [Diagnostics](#diagnostics), then [What happens by default](#what-happens-by-default) |

## What each request carries

What the package adds to a request depends on two things:

* the kind of host: a token-protected API domain, a secrets-only API domain, or a host not protected by Approov (one you have not added)
* the outcome of the attestation attempt for the request

Based on the attestation outcome and the kind of host, the package and its [service mutator](#service-mutators) decide what to add to the request. They also decide whether the request goes ahead at all.

| Request goes to | Outcome | What the package adds |
| :--- | :--- | :--- |
| a token-protected domain: an API domain you added to Approov | `SUCCESS` | the token header, and the trace header when the SDK gives a trace ID. Your secure strings, or the [status of each one that could not be fetched](#secure-strings). The signatures, once you install [message signing](#message-signing). A checked connection. |
| a secrets-only domain: an API domain you added with `approov api -add <domain> -noApproovToken` | `UNPROTECTED_URL` | your secure strings, or the status of each one that could not be fetched. A checked connection. No token or trace header, and no signatures. |
| a host not protected by Approov | `UNKNOWN_URL` | nothing. The connection relies on the device's trust store. |
| a token-fetch failure, to a host protected by Approov | a failure status | depends on the service mutator (see below) |
| a token-fetch failure, to a host not protected by Approov | a failure status | nothing (see below) |

A failure status means the app could not complete the attestation. For example, there was no network, or the Approov service could not be reached. The [service mutator](#what-happens-by-default) then decides whether the request fails in the app or is sent. A request that is sent carries the `Approov-Token` header with an empty token after any prefix. If you turned on [setUseApproovStatusIfNoToken](REFERENCE.md#setuseapproovstatusifnotoken), it carries the status name instead. It has no trace header and no secure strings.

For a host not protected by Approov, the request goes out unchanged, whatever the outcome. The standard mutators never fail it in the app. Only your own mutator can, by throwing from `handleRequestFetchTokenResult` (see [Service mutators](#service-mutators)).

The headers your backend may receive:

* `Approov-Token` carries the Approov token, or is empty (or holds the [status](REFERENCE.md#setuseapproovstatusifnotoken)) when no token could be fetched. Only your backend can tell from the token whether the app passed. See [Approov tokens](https://docs.approov.io/core-concepts/approov-tokens/architecture-and-security/).
* `Signature` and `Signature-Input` carry the signatures, once you install [message signing](#message-signing).
* `Approov-TraceID` is an optional debug header. Your backend passes it through unchanged.

Whatever the attestation outcome, the package checks the TLS connection to each domain you added, token-protected or secrets-only (see [Connection validation](#connection-validation)).

## What happens by default

For every request it processes, the Approov HTTP stack fetches an Approov token for the request URL. It does not process a request before `initialize` or in [bypass mode](#bypass-initialization), a WebSocket upgrade, or a request to an [excluded URL](#excluding-urls). It then applies the decisions of the installed [service mutator](#service-mutators). The package provides three standard ones:

* `ApproovServiceMutator.CLOSE_FAILURE` keeps the 3.5.x token decisions for your API domains. A failed token fetch fails the request in the app, with the same `ApproovException` types as 3.5.x.
* `ApproovServiceMutator.ALWAYS_PROCEED` never fails a request because of its token fetch. Whatever the token fetch outcome, the request is sent, and your backend decides. Your backend is then the enforcement point.
* `ApproovServiceMutator.DEFAULT` is the mutator installed out of the box. `setServiceMutator(null)` puts it back, and so does each `initialize` that succeeds. `DEFAULT` points to whatever the release considers default behaviour, which is currently `CLOSE_FAILURE`.

To opt in to always proceeding:

```java
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

In the table below, "an Approov protected host" means one of the API domains you added to Approov, of either kind.

| Approov token fetch status | `CLOSE_FAILURE` (default) | `ALWAYS_PROCEED` |
| :--- | :--- | :--- |
| `SUCCESS` | proceeds with the token, any trace header, the secure strings and, with message signing installed, the signatures | same |
| `UNPROTECTED_URL` (secrets-only API) | proceeds with the secure strings only, no Approov headers | same |
| `UNKNOWN_URL` (host not protected by Approov) | proceeds untouched | same |
| `NO_APPROOV_SERVICE`, Approov protected host | proceeds with an empty token header (or the status), but no trace header and no secure strings | same |
| `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`, Approov protected host | fails with `ApproovNetworkException`, which can be retried. This is a deprecated subclass of `ApproovFetchStatusException`, so catch `ApproovFetchStatusException` and read `getTokenFetchStatus()`. With `setUseApproovStatusIfNoToken(true)` it proceeds with the status in the token header instead | proceeds with an empty token header (or the status), but no trace header and no secure strings |
| any other status (`INTERNAL_ERROR`, `BAD_URL`, ...), Approov protected host | fails with `ApproovFetchStatusException` | proceeds with an empty token header (or the status), but no trace header and no secure strings |
| any failure status, host not protected by Approov, or any host before the app has its first Approov configuration | proceeds untouched, and no standard mutator fails it | same |

"The status" in this table means the status name in the token header, after any prefix, when you turn on [setUseApproovStatusIfNoToken](REFERENCE.md#setuseapproovstatusifnotoken). A request that goes ahead after a failed token fetch is signed too, if you installed [message signing](#message-signing).

`NO_APPROOV_SERVICE` means the app could not reach the Approov service or its failover. Requests to your API domains then go out with an empty token header (or the status) under either standard mutator.

These are the token fetch decisions only. Under either mutator, these still fail the request:

* a TLS connection that fails the check
* an abort that your own hooks ask for

A WebSocket upgrade request (`Upgrade: websocket`) goes out untouched. It gets no token fetch, no secure strings and no signature. See [Connection validation](#connection-validation) for its connection.

Volley delivers a failure to your `Response.ErrorListener`. An abort from the package arrives as an `ApproovException`, which is a Volley `AuthFailureError`. An abort that your own mutator makes arrives as an `ApproovException` too, with your exception as its cause. A failed TLS check arrives as Volley's `NoConnectionError`, with the `SSLPeerUnverifiedException` as its cause.

## Message signing

The signer, `ApproovDefaultMessageSigning`, adds RFC 9421 message signatures to every request that carries the Approov token header.

Message signing is **off unless you install it**. If you do not need signatures, keep the default and install nothing.

The signer is implemented as a service mutator, so installing another mutator, passing `null` to `setServiceMutator` or a successful `initialize` removes it. The signer makes the standard decisions, the same as `CLOSE_FAILURE`. If those suit you, give it a default factory and install it right after `initialize`, as in the example. To sign under other decisions, such as `ALWAYS_PROCEED`, use [`combined`](#sign-with-other-decisions).

```java
ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
```

Once the signer is installed, every request that carries the Approov token header is signed with the install signature, `ecdsa-p256-sha256`. It uses a key unique to the app installation, held in the Android Keystore. The Keystore keeps the private key in the device's secure hardware when the device has it. Its dictionary member is `install`.

You can add the account signature, `hmac-sha256`, with `setUseInstallAndAccountMessageSigning()` on the factory. It uses a shared account key, delivered to the app when it passes attestation. Its member is `account`. Both are members of the same `Signature` and `Signature-Input` headers, over the same covered components. If one signature cannot be produced, the request goes ahead with the other, or unsigned.

The package signs the URL in the normalized form that Android sends. Before Android sends a request, it percent-encodes some characters, such as `|` or a space in the path, and any character that is not ASCII. The package encodes the URL in the same way before it signs and sends the request. It keeps the escapes that are already in the URL, such as `%20`. So the package signs and sends `https://api.example.com/café?q=a|b` as `https://api.example.com/caf%C3%A9?q=a|b`. If the package cannot parse a URL, it sends the request as written and unsigned, and logs an error once.

The signed target URI, and the authority if you cover it, leave out a default port: `:443` for `https` and `:80` for `http`. So `https://api.example.com:443/v1` and `https://api.example.com/v1` give the same signature base.

The default factory covers `Content-Type` when the request sends it. A POST, PUT or PATCH request with a body sends the value of `getBodyContentType()`, or the `Content-Type` that `getHeaders()` gives, which has precedence. `Content-Length` is not a covered component, because the platform adds it after the package signs the request. Use the `Content-Digest` header to cover the body. The package adds it for POST, PUT and PATCH requests that have a body. Volley sends no body for any other method, so no digest is made for it, even if your `Request` returns a body.

A request to a secrets-only API that the SDK reports as `UNPROTECTED_URL` carries no token header and is not signed. A request to an Approov protected host can go ahead after a failed token fetch. It then still carries the token header, empty or with the status. So the signer signs it too, over that value.

Each `initialize` that succeeds puts back the `DEFAULT` mutator, which removes the signer. So install it again after each `initialize`.

To sign under decisions that `combined` does not offer, combine them with the signer in a mutator of your own. Your mutator makes its decisions and calls the signer from its `handleRequestProcessedHeaders`. This mutator makes the `ALWAYS_PROCEED` token decisions and signs:

```java
import com.criticalblue.approovsdk.Approov;

class ProceedAndSign implements ApproovServiceMutator {
    private final ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
            ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());

    @Override
    public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult result, String url)
            throws ApproovException {
        return ApproovServiceMutator.ALWAYS_PROCEED.handleRequestFetchTokenResult(result, url);
    }

    @Override
    public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
            ApproovRequestMutations changes) throws ApproovException {
        return signer.handleRequestProcessedHeaders(request, headers, changes);
    }
}

ApproovService.setServiceMutator(new ProceedAndSign());
```

When you write such a mutator:

* To change the headers before they are signed, make your change first and then call the signer.
* Let an exception from the signer propagate unchanged. A required body digest that cannot be generated then fails the request, as it does when the signer is installed on its own.
* The package runs your `handleRequestProcessedHeaders` on every attempt of a request, so keep it safe to repeat. See [Retries and held requests](#retries-and-held-requests).

Your backend receives `Signature` and `Signature-Input` headers whose members include `install`, `account` or both. When a signature cannot be produced, the request goes ahead with the other signature or unsigned. The package logs under the `ApproovMsgSign` tag: a missing install or account signature as a warning once per process, and a request sent unsigned as an error once per process. It logs later occurrences at debug level. Only a configuration error, such as a required body digest that cannot be generated, fails the request.

Your backend verifies the signatures as [Installation Message Signing](https://docs.approov.io/operations/message-signing/installation/) and [Account Message Signing](https://docs.approov.io/operations/message-signing/account/) describe.

### Sign with other decisions

`ApproovDefaultMessageSigning.combined(decisions)` returns a signer that adds both the install and the account signature. It makes the decisions of `decisions`: `ApproovServiceMutator.CLOSE_FAILURE`, `ALWAYS_PROCEED`, `DEFAULT` or a mutator of your own. `combined()` uses `ApproovServiceMutator.DEFAULT`, the same as `CLOSE_FAILURE`. If `decisions` is `null`, the call throws `IllegalArgumentException`. A signature that cannot be produced is left out, and the request goes ahead with the other signature or unsigned. Your backend can check the install signature only if the Approov token carries the install public key. Turn that on for your account with `approov policy -setInstallPubKey on` (see [installation message signing](https://docs.approov.io/operations/message-signing/installation/)). Each call returns a new `ApproovDefaultMessageSigning`, so `setDefaultFactory` and `putHostFactory` on it change only that signer.

```java
ApproovService.setServiceMutator(
        ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE));

ApproovService.setServiceMutator(
        ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
```

## Header names

You can change the name of the token header and the trace header, and the prefix in front of the token. By default, the token goes in `Approov-Token` with no prefix, and the trace ID in `Approov-TraceID`.

Change them when your backend expects the token in another header, such as `Authorization` with a `Bearer ` prefix, or does not want the trace header. Passing `null` turns the trace header off.

```java
ApproovService.setTokenHeader("Authorization", "Bearer ");   // default "Approov-Token", no prefix
ApproovService.setTraceIDHeader(null);                       // default "Approov-TraceID"; null disables
```

Each `initialize` that succeeds puts these back to their defaults, so set them after it.

## Bypass initialization

Initialize with an empty string instead of the account ID to start the package in bypass mode. In bypass mode the package is enabled but protects nothing: `isApproovServiceEnabled()` is `true` and `isApproovProtectionEnabled()` is `false`. In this mode:

* the stack from `getBaseHttpStack()` sends requests with no Approov processing. There is no token, signing, secure strings or Approov connection check, only OS trust.
* the methods that call the SDK throw `ApproovException` without calling it.

Before any `initialize`, the stack from `getBaseHttpStack()` works the same way. It is one stack for the life of the process. A queue built with it protects its requests once an `initialize` turns Approov on.

Bypass mode is a starting or fallback state. Use it, for example, while your app fetches the account ID remotely. The README example also uses it as a guard, in case the account ID does not reach the app intact.

```java
ApproovService.initialize(context, "");
```

A later `initialize` with the account ID turns Approov on at runtime, if the SDK accepts it. Like each `initialize` that succeeds, it resets the configuration to its defaults, so make your configuration calls again after it. A queue that you built with `getBaseHttpStack()` protects its requests from then on.

Once protection is on, the package ignores an `initialize` with an empty string, and resets nothing. The SDK rejects a later `initialize` with a different account ID or a different comment. Its exception reaches your code, and the package state is unchanged. See [initialize in the reference](REFERENCE.md#initialize).

In bypass mode, the `ApproovService` tag logs `initialize: bypass mode, Approov protection not active` at `INFO`.

## Initialize, then configure

You normally initialize the package once. Call `initialize` and handle any exception it throws. It is synchronous and does not need network access, so it returns without waiting for the network. Then make every configuration call your app needs, such as:

* the token, trace and binding headers, and `setUseApproovStatusIfNoToken`
* substitution headers and query parameters
* exclusion regular expressions
* the service mutator, and so message signing
* the logging level

Until your configuration calls run, requests use the defaults.

```java
ApproovService.initialize(getApplicationContext(), "<your-approov-account-id>");
ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
```

Configure immediately after `initialize`, before the app sends protected requests. The [README](README.md#initializing) shows where to call `initialize`.

Each `initialize` that succeeds resets these settings to their defaults:

* the token, trace and binding headers
* `setUseApproovStatusIfNoToken`
* the substitutions and the exclusions
* the service mutator

It also clears `getLastARC()`. It keeps the logging level. Any other setting made before `initialize` is lost.

Two kinds of `initialize` change nothing. The first has an empty account ID after protection is on, and the package ignores it. The second is one that the SDK rejects, for example a repeat call with a different account ID or a different comment. The SDK then throws `IllegalStateException`, which reaches your code.

Initialization can also be done for you, for example by a one-line native bootstrap in a React Native app. This is supported, but it configures nothing. It calls `initialize` with the account ID and comment, and that is all. Your app makes all the configuration calls afterwards, after the last `initialize`.

When the SDK initializes, `initialize` logs `initialize: Approov protection enabled` at `INFO`. When the SDK was already initialized with the same account ID and comment, it logs `initialize: Approov SDK already initialized with the same config and comment` at `DEBUG`.

## Token binding

[Token binding](https://docs.approov.io/backend-integration/token-binding/) ties the Approov token to the value of a header on the request, typically an OAuth `Authorization` header. A token then cannot be replayed with different credentials.

There is no binding header by default. Set one when your requests carry a credential header, such as an OAuth `Authorization` header, whose value changes rarely, such as a long-lived OAuth token. Each new value makes the package fetch a new token from the Approov service.

```java
ApproovService.setBindingHeader("Authorization");
```

Each request's token is bound to that request's own header value. This holds even when requests with different values are in flight at once, as during an OAuth token refresh.

The SDK holds one binding value for the whole app. So for every request that carries the binding header, the package sets the value and fetches the token as one step. It does this on every attempt of the request: the first one, a Volley retry and each redirect that the package protects. Do not call `setDataHashInToken` or `fetchToken` while requests that carry the binding header are in flight, as that can bind a token to the wrong value.

The call logs `setBindingHeader <name>` at `DEBUG` under the `ApproovService` tag, and the token your backend receives carries the `pay` claim.

## Secure strings

[Secure strings](https://docs.approov.io/backend-integration/secure-strings/) let you remove API keys and other secrets from your app. An app that passes attestation gets them at runtime from the Approov service. You put a placeholder in a request header or query parameter, and the package replaces it with the secret before the request is sent.

By default there are no substitution headers or query parameters, so a secure string placeholder goes out unchanged. Register the headers and query parameters whose values are secure string keys. The HTTP stack then substitutes them on every request, so you do not change your `Request` classes.

```java
ApproovService.addSubstitutionHeader("X-Api-Key", null);          // whole value is the key
ApproovService.addSubstitutionHeader("Authorization", "Bearer "); // value after the prefix is the key
ApproovService.addSubstitutionQueryParam("api_key");
```

If a value's secure string fetch fails, the value is replaced by the fetch status name and the request goes ahead. `UNKNOWN_KEY` is the exception: no secure string is defined for that value, so it is left as your app wrote it. Header names are matched without regard to case and a header cannot be both a binding header and a substitution header.

A secure string goes only into a request over `https` to a token-protected or secrets-only domain. A request to any other host keeps the placeholder. Two kinds of secure string are not substituted. A header cannot carry anything but a tab and printable ASCII. A URL cannot carry a space, a control or non-ASCII character, `&` or `#`. The placeholder stays, a warning names the header or query parameter without the value, and the request goes ahead.

Your backend receives the secret in place of the key. When it does not, two things give the reason: the value it receives, and the `Secure string not substituted` log line. The value is a status name such as `REJECTED`, or the key itself. Most of these log lines are at `DEBUG`, so set the logging level to `DEBUG` to see them (see [Diagnostics](#diagnostics)).

The stack substitutes headers and URL query parameters. It does not read the form parameters in the body of a POST. For those, the manual helper `substituteQueryParam(url, params, name)` is still available. Call it from `Request.getParams()`. The manual helpers `substituteHeader` and `substituteQueryParamInURLString` still work, but do not use them for headers and URL query parameters in new code. The automatic substitution also covers the redirects that the package follows (see [Redirects](#redirects)).

## Excluding URLs

Requests whose URL contains a match for an exclusion regular expression are sent untouched, without a token fetch. The expression is not anchored, and the package compares it with the full URL, query included. Use `^` and `$` to match the whole URL. The default `handleRequestShouldProcess` applies the exclusions, so a mutator that overrides it without calling the default drops them.

There are no exclusions by default. Use them for requests to your API domains that should not fetch a token, such as a health check.

```java
ApproovService.addExclusionURLRegex("^https://api\\.example\\.com/health.*");
```

Connection checks still apply to excluded requests on domains added to Approov. Each `initialize` that succeeds resets the exclusions.

`addExclusionURLRegex` logs the expression at `DEBUG`. An invalid regular expression is logged as an error and nothing is added.

## Connection validation

The HTTP stack checks the TLS connection to each domain you added to Approov. It checks against the certificate public keys configured for the domain. For a domain with none defined, it falls back to the Managed Trust Roots.

It is on by default for every domain you added to Approov. A request whose connection fails the check fails with `SSLPeerUnverifiedException`, which Volley delivers as a `NoConnectionError` with that exception as its cause. A certificate that OS trust rejects fails earlier, with `SSLHandshakeException`.

The package matches the pins against the certificate chain that the platform accepted for the host, not against any certificate the server sends. The package asks for the pins when each connection is made. A pin change applies to the next request.

The package asks the platform for one new connection per request. To do this, it sets `Connection: close` on every `https` request, so that the platform never reuses an earlier connection, and so every request is checked. If your `Request` sets a `Connection` header of its own, that header replaces this one. The check then runs only when the platform opens a new connection.

A WebSocket upgrade is not pinned by the package, as it is not processed by the package at all. A request that you [exclude](#excluding-urls) is still checked, unless your mutator turns the check off for it with `handlePinningShouldProcessRequest`. A request for which the hook returns `false` is checked by OS trust only. The package asks the hook for each request it sends, and for each redirect hop that it follows (see [Redirects](#redirects)).

For a redirect that the platform follows, the package asks the hook only for the first URL. This is the case for an excluded request and for a WebSocket upgrade. Each connection that these requests make is still checked.

If the SDK cannot give the pins, the connection continues on OS trust, which has already accepted it. The package logs one error under the `ApproovPinVerifier` tag. A request to a domain you added with no pins configured does the same, with one warning for each host.

A failure logs an error under the `ApproovPinVerifier` tag that names the host.

## Redirects

The package follows the redirects of each request that it processes. It does not leave this to the platform, because the platform would send the Approov token and the secure strings to the new host.

* Each hop is a new request. The package fetches a token for the URL of the hop and protects the hop again, from your own headers and placeholders. It does not copy what it added to the earlier hop.
* A hop to another origin (scheme, host or port) carries nothing that the package added: no token, no secure string and no signature. The package keeps your own headers, except `Authorization`, which it drops when the host or the port changes, as the platform does. If the new host is one of your API domains, the hop gets its own token.
* A hop to the same origin is protected again, and signed again if you installed message signing.
* The package follows 301, 302 and 303 for any method. A method that can carry a body, such as POST, becomes GET with no body. It follows 307 and 308 for GET and HEAD only. It never follows a redirect to another scheme, and it stops after 20 hops.
* The package uses the URL in `Location` as the server sent it. It never looks up a secure string in its query.

For an excluded request and for a WebSocket upgrade, the platform follows the redirects. The package adds nothing to such a request, so nothing is carried. The pinning hook is asked only for the first URL, but each connection is still checked.

## Retries and held requests

Volley has no stale protection refresh as OkHttp has, because none is needed. The package applies protection on every attempt, just before it connects. That covers the first attempt, each Volley retry and each redirect hop. A request that waits in the Volley queue, or that your app delays, gets a new token and a new signature when its attempt starts.

Each attempt starts from the headers that your `Request` returns. A retry therefore does not repeat the Approov headers of an earlier attempt.

A `Request` object that your app adds to a queue again keeps the service mutator that it started with. This holds even after `setServiceMutator` or `initialize`. To use a new mutator, build a new `Request`.

## Service mutators

A service mutator, an `ApproovServiceMutator`, is the object that holds the package's decisions, such as whether a failed token fetch fails the request. It has one method for each decision, and the package asks the installed mutator at each decision point. The standard mutators and their decisions are in [What happens by default](#what-happens-by-default).

Write your own mutator when your app needs a decision that the standard ones do not make. Every method has a default, so override only what you need. A mutator of your own that should never abort a request delegates the token decisions to `ApproovServiceMutator.ALWAYS_PROCEED`. A mutator you install, at any time, applies only to requests processed after the call.

The package's signer is also a mutator. To combine it with decisions of your own, see [Message signing](#message-signing).

The hooks:

| Hook | Decides |
| :--- | :--- |
| `handleRequestShouldProcess` | whether a request gets Approov processing at all (by default, every request that is not excluded) |
| `handleRequestFetchTokenResult` | given the token fetch result, whether to send the request with its Approov headers, send it without them, or abort it |
| `handleRequestHeaderSubstitutionResult`, `handleRequestQueryParamSubstitutionResult` | whether to apply a secure string substitution |
| `handleRequestProcessedHeaders` | final changes to the headers of the processed request. The signer signs here, so a mutator that calls it makes its own changes first |
| `handlePinningShouldProcessRequest` | whether Approov connection checks (Managed Trust Roots or configured public keys) apply to a request |
| `handlePrecheckResult`, `handleFetchTokenResult`, `handleFetchSecureStringResult`, `handleFetchCustomJWTResult` | how the direct methods turn a result into an exception |

A mutator aborts a request by throwing an `ApproovException` from a `handleRequest...` hook. `handlePinningShouldProcessRequest` declares no exception, so it aborts by throwing a `RuntimeException`. Your app receives an `ApproovException` with your exception as its cause.

This mutator turns the connection check off for one host:

```java
class SkipPinsForCdn implements ApproovServiceMutator {
    @Override
    public boolean handlePinningShouldProcessRequest(Request<?> request) {
        return !request.getUrl().startsWith("https://cdn.example.com/");
    }
}

ApproovService.setServiceMutator(new SkipPinsForCdn());
```

## Diagnostics

The package writes a diagnostic line for each token fetch, and for each secure string it does not deliver.

These lines are written at debug level, which is off by default (see [setLoggingLevel](REFERENCE.md#setlogginglevel)).

To write them, set the level in a debug build:

```java
ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
```

Or enable debug logging for the `ApproovService` tag, with no rebuild. This works on any installed build, including a release one. It raises any level except `OFF` to `DEBUG`, for all of the package's tags. It lasts until you set it back or the device reboots:

```sh
adb shell setprop log.tag.ApproovService DEBUG
```

The package never logs a token. For each request it processes, it logs the [loggable form](https://docs.approov.io/core-concepts/approov-tokens/architecture-and-security/#loggable-tokens) of the result. Its `arc` claim, the [Attestation Response Code](https://docs.approov.io/app-integration/frontend/attestation/#attestation-response-code), tells why attestation gave that result. The direct methods, such as `fetchToken`, log only the status. For example:

```
D/ApproovHurlStack: Token for https://api.example.com/v1/items: {"did":"...","exp":1757400000,"arc":"IXPSB7TRK26LXE3M", ...,"sip":"a1b2c3"}
```

The URL in the line is the request URL without its user info, query or fragment. So no query value, such as a substituted secure string or personal data, is logged.

To find the reasons behind an `arc`, see [decoding an Attestation Response Code](https://docs.approov.io/app-integration/frontend/attestation/#decoding-an-attestation-response-code). Your account's [metrics](https://docs.approov.io/operations/metrics-graphs/grafana-overview/) show the same results in aggregate. A [development signing certificate](https://docs.approov.io/operations/app-signing-certificates/development-and-testing/#development-app-signing-certificates) lets debug builds and emulators pass attestation.
