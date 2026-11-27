//
// MIT License
//
// Copyright (c) 2016-present, Approov Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package io.approov.service.volley;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.toolbox.HttpResponse;
import com.android.volley.toolbox.HurlStack;
import com.criticalblue.approovsdk.Approov;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

/**
 * Alternative HurlStack to be used for Approov that adds Approov tokens and pinning. This overrides certain
 * methods in the default stack to provide this functionality. The pinning approach used is immediately reactive
 * to pinning changes.
 * <p>
 * The token fetch status of the request URL decides what the request carries: on SUCCESS (a token-protected
 * API) the token and trace headers and any message signature; on UNPROTECTED_URL (a secrets-only API) and
 * UNKNOWN_URL (a host not added to Approov) no Approov header; and on a failure status the service mutator
 * decides whether the request is aborted or proceeds, for a listed host only (a key of the SDK pin set), with
 * the token header holding an empty token or the status and any trace header. A failure for a host that is
 * not listed is sent untouched unless the app's own mutator aborts it.
 */
class ApproovHurlStack extends HurlStack {
    // logging tag
    private static final String TAG = "ApproovHurlStack";

    /**
     * Constructs an new HurlStack that adds Approov tokens and pinning.
     */
    public ApproovHurlStack() {
        super();
    }

    /**
     * Sends a request with exactly the headers given, which include any the request gives in getHeaders(), so
     * that the request's own headers are not read again and never take precedence over those Approov sets.
     * This is also the test seam that sees what is sent.
     *
     * @param request is the request, or a view of one attempt of it
     * @param headers are all the headers to send
     * @return the response
     * @throws IOException if the request fails
     * @throws AuthFailureError if the request's body cannot be read
     */
    protected HttpResponse executeNetworkRequest(Request<?> request, Map<String, String> headers)
            throws IOException, AuthFailureError {
        return super.executeRequest(ApproovRequestView.of(request, headers), Collections.<String, String>emptyMap());
    }

    /**
     * Adds pinning to the connection by overriding the HostnameVerifier with something that pins
     * the connections. The connection must be for https.
     */
    @Override
    protected HttpURLConnection createConnection(URL url) throws IOException {
        HttpURLConnection connection = super.createConnection(url);

        // Workaround for the M release HttpURLConnection not observing the
        // HttpURLConnection.setFollowRedirects() property.
        // https://code.google.com/p/android/issues/detail?id=194495
        connection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());

        if (!ApproovService.isApproovEnabled()) {
            return connection;
        }

        // ensure the connection is pinned
        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
            PinningHostnameVerifier pinningHostnameVerifier = new PinningHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
            httpsConnection.setHostnameVerifier(pinningHostnameVerifier);

            // The HostnameVerifier (and therefore the live-pin check) only runs during the TLS
            // handshake of a NEW connection, never when HttpURLConnection reuses a pooled
            // keep-alive connection. Request "Connection: close" on pinned connections so each
            // request performs a fresh handshake: this guarantees a dynamic pin update (spec §4)
            // takes effect on the very next request instead of lingering on a connection that was
            // established under a now-superseded pin set.
            httpsConnection.setRequestProperty("Connection", "close");
        }

        return connection;
    }

    /**
     * Applies Approov protection to a request and sends it. If it is not currently possible to fetch an Approov
     * token for a protected host (typically due to no or poor network) the service mutator decides whether the
     * request fails, and a later retry should be made.
     */
    @Override
    public HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders)
            throws IOException, AuthFailureError {
        Map<String, String> cacheHeaders = (additionalHeaders == null)
                ? new LinkedHashMap<String, String>() : new LinkedHashMap<>(additionalHeaders);

        // before initialization and in bypass mode the request is sent without any Approov processing
        if (!ApproovService.isApproovProtectionEnabled())
            return sendUntouched(request, cacheHeaders);

        // check if we are to proceed with any Approov processing
        ApproovServiceMutator mutator = ApproovService.getServiceMutator();
        Map<String, String> hookHeaders = Collections.unmodifiableMap(new LinkedHashMap<>(cacheHeaders));
        if (!ApproovService.callMutator("handleRequestShouldProcess",
                () -> mutator.handleRequestShouldProcess(request, hookHeaders)))
            return sendUntouched(request, cacheHeaders);

        // protect the request for its URL and send it
        Attempt attempt = Attempt.first(request, cacheHeaders);
        Attempt sent = protect(attempt, mutator);
        return executeNetworkRequest(sent.view, sent.wireHeaders);
    }

    /**
     * Sends a request with no Approov processing, with its own headers over the cache headers, as HurlStack
     * would.
     *
     * @param request is the request
     * @param cacheHeaders are the cache headers Volley adds
     * @return the response
     * @throws IOException if the request fails
     * @throws AuthFailureError if the request's headers or body cannot be read
     */
    private HttpResponse sendUntouched(Request<?> request, Map<String, String> cacheHeaders)
            throws IOException, AuthFailureError {
        Map<String, String> headers = new LinkedHashMap<>(cacheHeaders);
        Map<String, String> appHeaders = request.getHeaders();
        if (appHeaders != null)
            putAllHeaders(headers, appHeaders);
        return executeNetworkRequest(request, headers);
    }

    /**
     * Protects one attempt of a request. A token is fetched for the attempt URL and the protection its status
     * allows is applied: on a token-protected API (SUCCESS) the token and trace headers and any message
     * signature; on a secrets-only API (UNPROTECTED_URL) nothing but what the processed headers hook adds; and on
     * a failure status the service mutator lets proceed the token header with an empty token or the status and
     * any trace header. An attempt that is not protected is returned with its own headers only.
     *
     * @param attempt is the attempt, carrying the app's own headers
     * @param mutator is the service mutator to consult
     * @return the attempt to send, with its wire headers
     * @throws ApproovException if the request is to be aborted
     */
    private Attempt protect(Attempt attempt, ApproovServiceMutator mutator) throws ApproovException {
        String url = attempt.url;
        Approov.TokenFetchResult approovResults = fetchToken(attempt);

        // provide information about the obtained token or error (note "approov token -check" can be used to
        // check the validity of the token and if you use token annotations they will appear here to determine
        // why a request is being rejected), only at debug level as the loggable token carries the device ID
        if (ApproovLog.isDebugEnabled())
            ApproovLog.d(TAG, "Token for " + ApproovLog.loggableURL(url) + ": " + approovResults.getLoggableToken());

        // the token fetch status decides the channel: SUCCESS is a token-protected API, UNPROTECTED_URL a
        // secrets-only API (added with -noApproovToken), UNKNOWN_URL a host not added to Approov and every
        // other status a failure
        Approov.TokenFetchStatus tokenStatus = approovResults.getStatus();
        Approov.TokenFetchResult tokenResults = approovResults;
        boolean tokenProtected = (tokenStatus == Approov.TokenFetchStatus.SUCCESS);
        boolean secretsOnly = (tokenStatus == Approov.TokenFetchStatus.UNPROTECTED_URL);
        boolean failure = !tokenProtected && !secretsOnly && (tokenStatus != Approov.TokenFetchStatus.UNKNOWN_URL);
        String host = ApproovService.loggableHost(url);
        if (failure && !ApproovService.isApproovApiHost(attempt.host())) {
            // a failure status says nothing about the host, so a host that is not an Approov API domain is
            // treated like UNKNOWN_URL and the request is sent untouched; the hook is still consulted so that
            // an app's own mutator may abort it, while the standard decisions never do
            Boolean decision = ApproovService.callMutator("handleRequestFetchTokenResult",
                    () -> mutator.handleRequestFetchTokenResult(tokenResults, url), true);
            if (decision == null)
                ApproovLog.d(TAG, "handleRequestFetchTokenResult: abort ignored for " + host
                        + ", not an Approov API domain");
            ApproovLog.d(TAG, "Approov token fetch for " + host + ": " + ApproovService.describeStatus(approovResults)
                    + ", not an Approov API domain, proceeding untouched");
            return attempt.untouched();
        }
        boolean proceedWithHeaders = ApproovService.callMutator("handleRequestFetchTokenResult",
                () -> mutator.handleRequestFetchTokenResult(tokenResults, url));
        if (tokenStatus == Approov.TokenFetchStatus.UNKNOWN_URL) {
            // a host not added to Approov has nothing added, whatever the mutator decided
            return attempt.untouched();
        }
        if (failure && !proceedWithHeaders) {
            // the mutator decided to send the request untouched on a failure status
            ApproovLog.d(TAG, "Approov token fetch for " + host + ": " + ApproovService.describeStatus(approovResults)
                    + ", proceeding with no Approov header");
            return attempt.untouched();
        }
        if (failure)
            ApproovLog.d(TAG, "Approov token fetch for " + host + ": " + ApproovService.describeStatus(approovResults)
                    + (ApproovService.getUseApproovStatusIfNoToken() ? ", proceeding with the status in the token header"
                    : ", proceeding with an empty token header"));

        // determine the headers to be added: the token and trace headers on any request the mutator lets
        // proceed with them, where after a failed fetch the token header holds an empty token or the status,
        // and none on a secrets-only request
        ApproovRequestMutations changes = new ApproovRequestMutations();
        Map<String, String> approovHeaders = new LinkedHashMap<>();
        if (proceedWithHeaders && !secretsOnly) {
            // the token header name and prefix are read together
            String[] tokenHeader = ApproovService.snapshotTokenHeader();
            String tokenHeaderKey = tokenHeader[0];
            String tokenPrefix = tokenHeader[1];
            if (tokenHeaderKey != null) {
                // a prefix a header cannot carry is an app configuration error, while such a token is an SDK
                // problem
                if (!ApproovService.isSafeHeaderValue(tokenPrefix))
                    throw ApproovService.unsafeHeaderValue(tokenHeaderKey);
                if (!ApproovService.isSafeHeaderValue(tokenResults.getToken()))
                    throw ApproovService.unsafeSdkValue("token", tokenHeaderKey);
                approovHeaders.put(tokenHeaderKey, ApproovService.buildTokenHeaderValue(tokenPrefix, approovResults));
                changes.setTokenHeaderKey(tokenHeaderKey);
                changes.setTokenHeaderPrefix(tokenPrefix);
            }

            // the trace header is sent whenever the SDK provides a trace ID, as evidence that Approov processing
            // occurred, while an empty trace ID is not sent
            String traceIDHeader = ApproovService.getTraceIDHeader();
            String traceID = approovResults.getTraceID();
            if ((traceIDHeader != null) && (traceID != null) && !traceID.isEmpty()) {
                if (!ApproovService.isSafeHeaderValue(traceID))
                    throw ApproovService.unsafeSdkValue("trace ID", traceIDHeader);
                approovHeaders.put(traceIDHeader, traceID);
                changes.setTraceIDHeaderKey(traceIDHeader);
            }
        }

        // the app's headers as sent, without any the layer sets itself, so that the processed headers hook and
        // any message signature see exactly what is sent
        Map<String, String> appHeaders = new LinkedHashMap<>(attempt.appHeaders);
        for (String name : approovHeaders.keySet())
            removeHeader(appHeaders, name);
        ApproovRequestView view = attempt.view.attempt(url, attempt.view.getMethod(), attempt.view.getBody(),
                appHeaders);

        // call the processed headers callback, which also signs the request when message signing is installed
        Map<String, String> headers = new LinkedHashMap<>(attempt.cacheHeaders);
        putAllHeaders(headers, approovHeaders);
        Map<String, String> before = new LinkedHashMap<>(headers);
        putAllHeaders(before, appHeaders);
        Map<String, String> processed = ApproovService.callMutator("handleRequestProcessedHeaders",
                () -> mutator.handleRequestProcessedHeaders(view, headers, changes));
        if (processed == null) {
            // a null result is a programming error in the callback, treated like a runtime exception from it
            String message = "ApproovServiceMutator.handleRequestProcessedHeaders returned null";
            ApproovLog.e(TAG, message);
            throw new ApproovException(message);
        }

        // a header the callback set or changed that a header cannot carry is an app configuration error
        for (Map.Entry<String, String> entry : processed.entrySet()) {
            String value = entry.getValue();
            if ((value != null) && !value.equals(header(before, entry.getKey()))
                    && !ApproovService.isSafeHeaderValue(value))
                throw ApproovService.unsafeHeaderValue(entry.getKey());
        }

        // the app's headers take precedence over the cache headers, and the processed headers over both
        Map<String, String> wireHeaders = new LinkedHashMap<>(attempt.cacheHeaders);
        putAllHeaders(wireHeaders, appHeaders);
        putAllHeaders(wireHeaders, processed);
        return attempt.sent(view, wireHeaders);
    }

    /**
     * Fetches the token for an attempt, bound to the value of the token binding header if the request carries
     * it.
     *
     * @param attempt is the attempt
     * @return the fetch result, never null
     * @throws ApproovException if the SDK fails or returns no result
     */
    private static Approov.TokenFetchResult fetchToken(Attempt attempt) throws ApproovException {
        String bindingHeader = ApproovService.getBindingHeader();
        String bindingValue = (bindingHeader != null) ? attempt.appHeaders.get(bindingHeader) : null;
        if (bindingValue != null) {
            try {
                Approov.setDataHashInToken(bindingValue);
            } catch (RuntimeException e) {
                ApproovService.recordLastARC(null);
                throw ApproovService.sdkFailure("setDataHashInToken", e);
            }
        }
        return fetchForRequest("fetchApproovTokenAndWait", () -> Approov.fetchApproovTokenAndWait(attempt.url));
    }

    /**
     * Performs a token or secure string fetch for a request and records its ARC. A RuntimeException from
     * the SDK, or a fetch that returns no result, is thrown as an ApproovException and leaves no ARC.
     *
     * @param call is the name of the SDK method, for the exception message
     * @param fetch is the SDK call
     * @return the fetch result, never null
     * @throws ApproovException if the SDK throws or returns no result
     */
    static Approov.TokenFetchResult fetchForRequest(String call, ApproovService.SdkFetch fetch)
            throws ApproovException {
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetch.fetch();
        } catch (RuntimeException e) {
            ApproovService.recordLastARC(null);
            throw ApproovService.sdkFailure(call, e);
        }
        if (approovResults == null) {
            ApproovService.recordLastARC(null);
            throw ApproovService.sdkNoResult(call);
        }
        ApproovService.recordLastARC(approovResults);
        return approovResults;
    }

    /**
     * Gets the value of a header without regard to the case of its name.
     *
     * @param headers are the headers
     * @param name is the header name
     * @return the value, or null if the header is absent
     */
    static String header(Map<String, String> headers, String name) {
        String value = headers.get(name);
        if (value != null)
            return value;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey()))
                return entry.getValue();
        }
        return null;
    }

    /**
     * Removes a header without regard to the case of its name.
     *
     * @param headers are the headers
     * @param name is the header name
     */
    static void removeHeader(Map<String, String> headers, String name) {
        List<String> keys = new ArrayList<>();
        for (String key : headers.keySet()) {
            if (name.equalsIgnoreCase(key))
                keys.add(key);
        }
        for (String key : keys)
            headers.remove(key);
    }

    /**
     * Sets headers, each replacing any header of the same name without regard to case, as the network stack
     * holds one value per header name.
     *
     * @param headers are the headers to change
     * @param values are the headers to set
     */
    static void putAllHeaders(Map<String, String> headers, Map<String, String> values) {
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (entry.getKey() == null)
                continue;
            removeHeader(headers, entry.getKey());
            headers.put(entry.getKey(), entry.getValue());
        }
    }

    /**
     * One network attempt of an app's request: its URL, the app's own headers, the cache headers Volley adds and,
     * once it is protected, what is sent.
     */
    static final class Attempt {
        // the view of the attempt carrying the app's request, URL, method and body
        final ApproovRequestView view;
        // the URL of the attempt
        final String url;
        // the app's own headers, with any placeholders as the app wrote them
        final Map<String, String> appHeaders;
        // the cache headers Volley adds
        final Map<String, String> cacheHeaders;
        // the headers sent, once protected
        final Map<String, String> wireHeaders;

        private Attempt(ApproovRequestView view, String url, Map<String, String> appHeaders,
                Map<String, String> cacheHeaders, Map<String, String> wireHeaders) {
            this.view = view;
            this.url = url;
            this.appHeaders = appHeaders;
            this.cacheHeaders = cacheHeaders;
            this.wireHeaders = wireHeaders;
        }

        /**
         * Reads the first attempt of an app's request, its headers and body read once.
         *
         * @param request is the app's request
         * @param cacheHeaders are the cache headers Volley adds
         * @return the first attempt
         * @throws AuthFailureError if the request's headers or body cannot be read
         */
        static Attempt first(Request<?> request, Map<String, String> cacheHeaders) throws AuthFailureError {
            Map<String, String> appHeaders = new LinkedHashMap<>();
            Map<String, String> requestHeaders = request.getHeaders();
            if (requestHeaders != null)
                putAllHeaders(appHeaders, requestHeaders);
            ApproovRequestView view = ApproovRequestView.of(request, appHeaders);
            return new Attempt(view, view.getUrl(), appHeaders, cacheHeaders, null);
        }

        // gets the host of the attempt URL, or null if it has none
        String host() {
            try {
                return new URL(url).getHost();
            } catch (MalformedURLException e) {
                return null;
            }
        }

        // gets the attempt sent with the app's own headers only
        Attempt untouched() {
            Map<String, String> headers = new LinkedHashMap<>(cacheHeaders);
            putAllHeaders(headers, appHeaders);
            return sent(view.withHeaders(appHeaders), headers);
        }

        // gets the attempt sent as the view gives it, with the given wire headers
        Attempt sent(ApproovRequestView sentView, Map<String, String> headers) {
            return new Attempt(sentView, sentView.getUrl(), appHeaders, cacheHeaders, headers);
        }
    }
}
