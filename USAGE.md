# Usage

This document describes the features and functionality of the Approov Service for Volley. It focuses on how to integrate the `BaseHttpStack`, how to customize request handling with `ApproovServiceMutator`, and how to enable HTTP message signing. For a basic end-to-end integration example, please refer to the [Quickstart guide](https://github.com/approov/quickstart-android-java-volley).

# Migrating from Earlier Releases

If you are upgrading from a release that predates the `ApproovServiceMutator` support, please review the following behavioral changes:

- `setProceedOnNetworkFail()` no longer has any effect. Requests now fail with an `ApproovNetworkException` on retryable network failures (`NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`) unless you enable `setUseApproovStatusIfNoToken(true)` or install a custom mutator. If your app previously relied on `setProceedOnNetworkFail(true)`, you must adopt one of these replacements to retain that behavior. See [Proceed on network failure](#proceed-on-network-failure-and-send-the-status-instead-of-the-jwt).
- `substituteHeader(...)` and `substituteQueryParam(...)` now require the request URL as their first argument so substitutions can be skipped for URLs that are not protected by Approov. The previous overloads without the URL have been removed and integrations must be updated when upgrading.
- `getBaseHttpStack()` now returns `null` when the service layer was initialized with an empty configuration string (bypass mode). Passing the `null` to `Volley.newRequestQueue(...)` selects the standard Volley stack, so existing integration code continues to work unchanged.
- `initialize(...)` now throws an `IllegalArgumentException` when the configuration string is `null`; pass `""` to request bypass mode explicitly.

# Basic Integration

Initialize Approov once during app startup, then create your Volley `RequestQueue` with the Approov-provided `BaseHttpStack`.

```java
import android.util.Log;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.Volley;
import java.util.UUID;

import io.approov.service.volley.ApproovService;

public final class MyApp extends android.app.Application {
    private static final String TAG = "MyApp";

    @Override
    public void onCreate() {
        super.onCreate();

        // App-generated id to correlate this install/session across your app logs and backend
        // (a UUID or any session/user identifier — it is NOT an Approov secret).
        String correlationId = UUID.randomUUID().toString();

        // Initialization can fail (bad config / SDK error). Guard it and fall back to bypass
        // mode (empty config) rather than letting the app crash.
        try {
            ApproovService.initialize(this, "<your-config-string>");
            if (ApproovService.isApproovEnabled()) {
                Log.i(TAG, "Approov initialized; deviceID=" + ApproovService.getDeviceID()
                        + " session=" + correlationId);
            } else {
                Log.w(TAG, "Approov initialized in bypass mode (no protection); session=" + correlationId);
            }
        } catch (Exception e) {
            // Continue UNPROTECTED — requests go out without Approov protection; backend stays the enforcement point.
            Log.e(TAG, "Approov init failed (session=" + correlationId + "); continuing unprotected", e);
            ApproovService.initialize(this, "");
        }

        // getBaseHttpStack() returns null in bypass mode, which selects the standard Volley stack.
        RequestQueue queue = Volley.newRequestQueue(
            this,
            ApproovService.getBaseHttpStack()
        );
    }
}
```

When you use the Approov `BaseHttpStack`:

- Approov tokens are fetched and attached to protected requests.
- Dynamic pinning is applied to HTTPS connections.
- Optional mutator logic can customize how requests are handled.
- Optional message signing can add `Signature` and `Signature-Input` headers.

# Approov Service Mutator

The `ApproovServiceMutator` allows you to customize the behavior of the Volley service layer at key points in the request lifecycle. You can override only the hooks you need and delegate the rest to the default behavior.

## Why use a mutator

- Centralize app-specific policy without forking the service layer.
- Decide whether requests should continue on particular Approov statuses.
- Add telemetry when attestation or secure string fetches fail.
- Replace the Approov JWT with a fetch status value when you intentionally proceed without a token.
- Compose message signing with other request mutations.

## Install a mutator

```java
import io.approov.service.volley.ApproovService;
import io.approov.service.volley.ApproovServiceMutator;

public final class MyMutator implements ApproovServiceMutator {
    // Override only the hooks you need.
}

ApproovService.setServiceMutator(new MyMutator());
```

Pass `null` to `setServiceMutator` to restore the default behavior.

## Default request behavior

By default, the Approov Volley stack behaves as follows when `Approov.fetchApproovTokenAndWait()` runs for a request:

| Approov Fetch Status | Default Action | Result |
| :--- | :--- | :--- |
| `SUCCESS` | Proceed | The request is sent with the `Approov-Token` header. |
| `NO_NETWORK` / `POOR_NETWORK` / `MITM_DETECTED` | Throw | An `ApproovNetworkException` is thrown and the request should be retried later. |
| `NO_APPROOV_SERVICE` / `UNKNOWN_URL` / `UNPROTECTED_URL` | Proceed | The request is sent without an `Approov-Token` header. |
| Other failure statuses | Throw | An `ApproovFetchStatusException` is thrown. |

This behavior is implemented by `ApproovServiceMutator.DEFAULT`.

## Prevent access without a token

If you want to stop requests when the SDK cannot reach the Approov service, override `handleRequestFetchTokenResult`.

```java
import com.criticalblue.approovsdk.Approov;

import io.approov.service.volley.ApproovNetworkException;
import io.approov.service.volley.ApproovServiceMutator;

public final class EnforceTokenMutator implements ApproovServiceMutator {
    @Override
    public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
        if (approovResults.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
            throw new ApproovNetworkException(
                approovResults.getStatus(),
                "Approov service unavailable for " + url
            );
        }
        return ApproovServiceMutator.DEFAULT.handleRequestFetchTokenResult(approovResults, url);
    }
}
```

## Proceed on network failure and send the status instead of the JWT

`setProceedOnNetworkFail()` is deprecated and no longer has any effect; calling it does not change request handling. Use the compatibility helper below or a custom mutator instead.

If you want the default mutator to treat retryable token fetch failures as "proceed with a status value instead of a JWT", you can enable the compatibility helper:

```java
ApproovService.setUseApproovStatusIfNoToken(true);
```

With that flag enabled, the default Volley stack:

- proceeds on `NO_NETWORK`, `POOR_NETWORK`, and `MITM_DETECTED`
- uses the fetch status as the configured Approov token header value when the SDK returns no token
- also forwards fallback statuses such as `NO_APPROOV_SERVICE` when a request otherwise proceeds without a token

Use a custom mutator if you need narrower control over which statuses are allowed through.

If you want a request to continue on networking failures and you also want the backend to see the exact Approov failure status in the configured Approov token header, override:

- `handleRequestFetchTokenResult(...)` to allow the request to proceed
- `handleRequestTokenHeaderValue(...)` to use `ApproovService.getApproovTokenHeaderValueOrStatus(...)`

```java
import com.criticalblue.approovsdk.Approov;

import io.approov.service.volley.ApproovService;
import io.approov.service.volley.ApproovServiceMutator;

public final class OfflineFallbackMutator implements ApproovServiceMutator {
    @Override
    public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
        switch (approovResults.getStatus()) {
            case SUCCESS:
                return true;
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                return true;
            default:
                return ApproovServiceMutator.DEFAULT.handleRequestFetchTokenResult(approovResults, url);
        }
    }

    @Override
    public String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url) {
        return ApproovService.getApproovTokenHeaderValueOrStatus(approovResults);
    }
}
```

This allows your backend to distinguish:

- a normal request carrying a real Approov JWT
- a request that intentionally proceeded with a known Approov failure such as `NO_NETWORK`
- a request where the header is missing unexpectedly

If the SDK returns an empty token for an otherwise accepted fetch, `ApproovService.getApproovTokenHeaderValueOrStatus(...)` also falls back to the fetch status string so the header still carries an explicit value.

## Add custom headers after Approov processing

You can override `handleRequestProcessedHeaders(...)` to add or adjust headers after Approov has prepared the request.

```java
import com.android.volley.Request;

import java.util.LinkedHashMap;
import java.util.Map;

import io.approov.service.volley.ApproovRequestMutations;
import io.approov.service.volley.ApproovServiceMutator;

public final class CustomHeaderMutator implements ApproovServiceMutator {
    @Override
    public Map<String, String> handleRequestProcessedHeaders(
        Request<?> request,
        Map<String, String> headers,
        ApproovRequestMutations changes
    ) {
        Map<String, String> mutated = new LinkedHashMap<>(headers);
        mutated.put("X-Client-Platform", "android");
        return mutated;
    }
}
```

If you are also using message signing, delegate to the signer first and then apply any extra headers.

```java
import com.android.volley.Request;

import java.util.LinkedHashMap;
import java.util.Map;

import io.approov.service.volley.ApproovDefaultMessageSigning;
import io.approov.service.volley.ApproovRequestMutations;
import io.approov.service.volley.ApproovServiceMutator;

public final class SignedMutator implements ApproovServiceMutator {
    private final ApproovServiceMutator signer;

    public SignedMutator() {
        signer = new ApproovDefaultMessageSigning()
            .setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
            );
    }

    @Override
    public Map<String, String> handleRequestProcessedHeaders(
        Request<?> request,
        Map<String, String> headers,
        ApproovRequestMutations changes
    ) throws io.approov.service.volley.ApproovException {
        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, headers, changes);
        Map<String, String> mutated = new LinkedHashMap<>(signed);
        mutated.put("X-Client-Platform", "android");
        return mutated;
    }
}
```

# Message Signing

It is possible to sign HTTP requests using Approov to ensure integrity and authenticity. The Volley port supports:

1. Installation message signing using the device-specific install key.
2. Account message signing using the account-level shared signing key.

Message signing is not enabled unless you install an `ApproovDefaultMessageSigning` mutator.

## Enable with default settings

```java
import io.approov.service.volley.ApproovDefaultMessageSigning;
import io.approov.service.volley.ApproovService;

ApproovDefaultMessageSigning signer =
    new ApproovDefaultMessageSigning().setDefaultFactory(
        ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
    );

ApproovService.setServiceMutator(signer);
```

The default factory:

- signs `@method` and `@target-uri`
- uses install message signing
- adds `created`
- adds a short `expires` lifetime
- includes the Approov token header
- includes the optional Approov TraceID header
- signs selected request headers when present
- adds a `Content-Digest` header for requests with a body

## Customize signing behavior

```java
import io.approov.service.volley.ApproovDefaultMessageSigning;

ApproovDefaultMessageSigning.SignatureParametersFactory factory =
    new ApproovDefaultMessageSigning.SignatureParametersFactory()
        .setUseAccountMessageSigning()
        .setAddCreated(true)
        .setExpiresLifetime(60)
        .setAddApproovTokenHeader(true)
        .addOptionalHeaders("Authorization", "Content-Type");

ApproovDefaultMessageSigning signer =
    new ApproovDefaultMessageSigning()
        .setDefaultFactory(factory)
        .putHostFactory("api.example.com", factory);
```

## Missing install keypair behavior

If install message signing cannot obtain the device install signature, the Volley signer logs the failure and skips message signing for that request instead of aborting the request. This matches the newer OkHttp behavior and allows the backend to decide how to handle the unsigned request.

# Token Binding

[Token Binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) binds the Approov token to a stable value such as an `Authorization` header.

```java
ApproovService.setBindingHeader("Authorization");
```

If the binding value changes, the SDK fetches a new bound token when required.

# Secure Strings Helpers

Volley often constructs headers, parameters, and URLs inside request subclasses. The service provides helpers that you can call from those request methods.

## Header substitution

Call `substituteHeader(...)` from `Request.getHeaders()`.

```java
@Override
public Map<String, String> getHeaders() throws AuthFailureError {
    Map<String, String> headers = new HashMap<>();
    headers.put("Api-Key", "your-secure-string-key");
    ApproovService.substituteHeader(this.getUrl(), headers, "Api-Key", null);
    return headers;
}
```

## Form/query parameter substitution

Call `substituteQueryParam(...)` from `Request.getParams()`.

```java
@Override
protected Map<String, String> getParams() throws AuthFailureError {
    Map<String, String> params = new HashMap<>();
    params.put("api_key", "your-secure-string-key");
    ApproovService.substituteQueryParam(this.getUrl(), params, "api_key");
    return params;
}
```

## URL query substitution

If the query parameter is part of the request URL string itself, call `substituteQueryParamInURLString(...)` before issuing the request or while overriding `getUrl()`.

```java
@Override
public String getUrl() {
    try {
        return ApproovService.substituteQueryParamInURLString(
            super.getUrl(),
            "api_key"
        );
    } catch (io.approov.service.volley.ApproovException e) {
        throw new RuntimeException(e);
    }
}
```

# Tips

- Install the mutator once during startup and keep its behavior stable.
- Keep mutator logic fast and side-effect safe because it runs on the request path.
- Use `getApproovTokenHeaderValueOrStatus(...)` only when you have explicitly decided that proceeding without a real token is acceptable.
- Prefer `ApproovFetchStatusException` for new error handling; `ApproovNetworkException` is retained for compatibility.
- Use the [Quickstart](https://github.com/approov/quickstart-android-java-volley) for a minimal example and this document for customization patterns.
