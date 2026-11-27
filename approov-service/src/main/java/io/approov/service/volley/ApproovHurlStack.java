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
import com.android.volley.Header;
import com.android.volley.Request;
import com.android.volley.toolbox.HttpResponse;
import com.android.volley.toolbox.HurlStack;
import com.criticalblue.approovsdk.Approov;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

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

    // the maximum number of redirects followed for one request, as HttpURLConnection follows
    static final int MAX_FOLLOW_UPS = 20;

    // how the attempt this thread is sending is connected, as HurlStack creates the connection on the thread
    // that sends it and createConnection is not given the request
    private static final ThreadLocal<AttemptConnection> sending = new ThreadLocal<>();

    // the service mutator each request was first processed with, so that a mutator change while a request is in
    // flight never applies to its later attempts, such as a redirect or a Volley retry
    private static final Map<Request<?>, ApproovServiceMutator> requestMutators = new WeakHashMap<>();

    /**
     * Constructs an new HurlStack that adds Approov tokens and pinning.
     */
    public ApproovHurlStack() {
        super();
    }

    /**
     * Gets the service mutator for a request, which is the one in force when the layer first processed it.
     *
     * @param request is the app's request
     * @return the service mutator for the request, never null
     */
    static ApproovServiceMutator mutatorFor(Request<?> request) {
        synchronized (requestMutators) {
            ApproovServiceMutator mutator = requestMutators.get(request);
            if (mutator == null) {
                mutator = ApproovService.getServiceMutator();
                requestMutators.put(request, mutator);
            }
            return mutator;
        }
    }

    /**
     * Forgets the service mutator of every request, so that each request is next processed with the mutator in
     * force. This should only be used for testing.
     */
    static void forgetRequestMutators() {
        synchronized (requestMutators) {
            requestMutators.clear();
        }
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
     * the connections, unless the service mutator opted the attempt out of pinning. Only an https
     * connection is pinned.
     */
    @Override
    protected HttpURLConnection createConnection(URL url) throws IOException {
        HttpURLConnection connection = super.createConnection(url);
        AttemptConnection attempt = sending.get();

        // the layer follows the redirects of a request it processes itself, as the platform would carry every
        // Approov header and substituted secure string to the redirect target; any other request follows them
        // as the platform does (the instance setting also works around the M release HttpURLConnection not
        // observing the HttpURLConnection.setFollowRedirects() property,
        // https://code.google.com/p/android/issues/detail?id=194495)
        connection.setInstanceFollowRedirects(((attempt == null) || !attempt.followsInLayer)
                && HttpURLConnection.getFollowRedirects());

        if (!ApproovService.isApproovProtectionEnabled()) {
            return connection;
        }

        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;

            // ensure the connection is pinned, unless the attempt opted out; a connection not made for an
            // attempt this stack sends is pinned, as the pinning hook can only remove pinning
            if ((attempt == null) || attempt.pinned) {
                PinningHostnameVerifier pinningHostnameVerifier = new PinningHostnameVerifier(
                        HttpsURLConnection.getDefaultHostnameVerifier());
                httpsConnection.setHostnameVerifier(pinningHostnameVerifier);
                if (attempt != null)
                    attempt.verifier = pinningHostnameVerifier;
            }

            // the pins are checked by the HostnameVerifier, which runs only in the TLS handshake of a new
            // connection, never when HttpURLConnection reuses a pooled keep-alive connection; a pool that is not
            // keyed by the verifier (the JVM's is not) would let a pinned request reuse a connection that an
            // opted-out request or an older pin set opened, without a check, so every connection, pinned or not,
            // asks the server to close it after the response and each request starts with a handshake its own
            // verifier checks
            httpsConnection.setRequestProperty("Connection", "close");
        }

        return connection;
    }

    /**
     * Applies Approov protection to a request and sends it. If it is not currently possible to fetch an Approov
     * token for a protected host (typically due to no or poor network) the service mutator decides whether the
     * request fails, and a later retry should be made.
     * <p>
     * Redirects of a request the layer processes are followed here as HttpURLConnection would follow them when
     * HttpURLConnection.getFollowRedirects() is true: 300 to 303 for any method, a method that permits a body
     * becoming GET without one, 307 and 308 for GET and HEAD, never to another scheme, and at most 20
     * follow-ups. Each hop drops Authorization on a change of host or port, as the platform does, and is
     * evaluated as a new request for its URL: the protection added for the previous hop is not carried, and the
     * hop is protected afresh from the app's own headers and placeholders if Approov protects its URL.
     */
    @Override
    public HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders)
            throws IOException, AuthFailureError {
        Map<String, String> cacheHeaders = (additionalHeaders == null)
                ? new LinkedHashMap<String, String>() : new LinkedHashMap<>(additionalHeaders);

        // before initialization and in bypass mode the request is sent without any Approov processing
        if (!ApproovService.isApproovProtectionEnabled())
            return sendUntouched(request, cacheHeaders);

        // WebSockets are not supported, so an upgrade is sent untouched (no token fetch, no Approov headers, no
        // secure string substitution, no signature and no Approov pinning, as the pinning hook is not asked), so
        // that nothing Approov issues travels on a connection the layer does not handle as an HTTP request
        Attempt attempt = Attempt.first(request, cacheHeaders);
        String upgrade = header(attempt.appHeaders, "Upgrade");
        if (upgrade == null)
            upgrade = header(cacheHeaders, "Upgrade");
        if ("websocket".equalsIgnoreCase((upgrade != null) ? upgrade.trim() : null)) {
            ApproovLog.d(TAG, "WebSocket upgrade to " + ApproovService.loggableHost(attempt.url)
                    + " sent without Approov processing (not supported)");
            return send(attempt.untouched(), false, false);
        }

        // check if we are to proceed with any Approov processing, under the mutator in force when the layer
        // first processed the request, which governs all its attempts
        ApproovServiceMutator mutator = mutatorFor(request);
        Map<String, String> hookHeaders = Collections.unmodifiableMap(new LinkedHashMap<>(cacheHeaders));
        if (!ApproovService.callMutator("handleRequestShouldProcess",
                () -> mutator.handleRequestShouldProcess(request, hookHeaders))) {
            Attempt untouched = attempt.untouched();
            return send(untouched, false, shouldPin(untouched, mutator));
        }

        // protect the request for its URL and send it, then follow any redirect, each hop protected for its own
        // URL
        Attempt sent = protect(attempt, mutator, true);
        int followUps = 0;
        while (true) {
            HttpResponse response = send(sent, true, shouldPin(sent, mutator));
            Attempt next = attempt.redirect(response);
            if (next == null)
                return response;
            close(response);
            if (++followUps > MAX_FOLLOW_UPS)
                throw new ProtocolException("Too many follow-up requests: " + followUps);
            ApproovLog.d(TAG, "Following redirect " + response.getStatusCode() + " to "
                    + ApproovLog.loggableURL(next.url));

            // the hop is a new request for its URL: excluded, or protected for it from the app's own headers
            attempt = next;
            ApproovRequestView hopView = attempt.view;
            if (ApproovService.callMutator("handleRequestShouldProcess",
                    () -> mutator.handleRequestShouldProcess(hopView, hookHeaders)))
                sent = protect(attempt, mutator, false);
            else
                sent = attempt.untouched();
        }
    }

    /**
     * Asks the service mutator whether Approov pinning applies to an attempt, with the attempt as it is sent.
     *
     * @param sent is the attempt to send
     * @param mutator is the service mutator the request was first processed with
     * @return true if the attempt is to be pinned, false for OS trust only
     * @throws ApproovException if the mutator aborts the request, reported as a hook failure naming the hook
     */
    private static boolean shouldPin(Attempt sent, ApproovServiceMutator mutator) throws ApproovException {
        ApproovRequestView view = sent.view;
        return ApproovService.callMutator("handlePinningShouldProcessRequest",
                () -> mutator.handlePinningShouldProcessRequest(view));
    }

    /**
     * Sends one network attempt with its wire headers, connected as given.
     *
     * @param sent is the attempt to send
     * @param followsInLayer is true if the layer follows its redirects, false if the platform does
     * @param pinned is true if Approov pinning applies to its connection
     * @return the response
     * @throws IOException if the request fails
     * @throws AuthFailureError if the request's body cannot be read
     */
    private HttpResponse send(Attempt sent, boolean followsInLayer, boolean pinned)
            throws IOException, AuthFailureError {
        AttemptConnection previous = sending.get();
        AttemptConnection connection = new AttemptConnection(followsInLayer, pinned);
        sending.set(connection);
        try {
            return executeNetworkRequest(sent.view, sent.wireHeaders);
        } catch (IOException e) {
            // a connection the Approov pins rejected fails with the platform pinning exception, which names the
            // host and never a pin, whatever exception the platform raised for the rejected host
            PinningHostnameVerifier verifier = connection.verifier;
            SSLPeerUnverifiedException failure = (verifier != null) ? verifier.failure() : null;
            if ((failure == null) || (failure == e))
                throw e;
            if (failure.getCause() == null)
                failure.initCause(e);
            throw failure;
        } finally {
            if (previous == null)
                sending.remove();
            else
                sending.set(previous);
        }
    }

    // closes the content of a response that is not returned, which releases its connection
    private static void close(HttpResponse response) {
        InputStream content = response.getContent();
        if (content == null)
            return;
        try {
            content.close();
        } catch (IOException e) {
            ApproovLog.d(TAG, "Redirect response not closed: " + e);
        }
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
     * <p>
     * Secure strings are substituted only on a protected channel, a token-protected or secrets-only API over
     * TLS, so that a request to any other URL carrying a placeholder never receives the secret. A secure string
     * fetch that fails while the request continues puts its status in place of the placeholder, as evidence for
     * the backend, and every placeholder not given a secure string is logged by name, never by value. The query
     * of a redirect target is the server's, so its values are never looked up as secure string keys.
     *
     * @param attempt is the attempt, carrying the app's own headers with their placeholders
     * @param mutator is the service mutator to consult
     * @param appQuery is true if the query of the attempt URL is the app's own, false if it is a redirect
     * target the server sent
     * @return the attempt to send, with its wire headers
     * @throws ApproovException if the request is to be aborted
     */
    private Attempt protect(Attempt attempt, ApproovServiceMutator mutator, boolean appQuery)
            throws ApproovException {
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
        String undelivered = undeliveredReason(url, approovResults);
        boolean undeliveredWarns = isConfigurationReason(url, tokenStatus);
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
            logUndeliveredPlaceholders(attempt, undelivered, undeliveredWarns, appQuery);
            return attempt.untouched();
        }
        boolean proceedWithHeaders = ApproovService.callMutator("handleRequestFetchTokenResult",
                () -> mutator.handleRequestFetchTokenResult(tokenResults, url));
        if (tokenStatus == Approov.TokenFetchStatus.UNKNOWN_URL) {
            // a host not added to Approov has nothing added or substituted, whatever the mutator decided
            logUndeliveredPlaceholders(attempt, undelivered, undeliveredWarns, appQuery);
            return attempt.untouched();
        }
        if (failure && !proceedWithHeaders) {
            // the mutator decided to send the request untouched on a failure status, so it also carries no
            // secure strings
            ApproovLog.d(TAG, "Approov token fetch for " + host + ": " + ApproovService.describeStatus(approovResults)
                    + ", proceeding with no Approov header");
            logUndeliveredPlaceholders(attempt, undelivered, undeliveredWarns, appQuery);
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

        // we now deal with any header substitutions, which may require further fetches but these should be
        // using cached results; the app's own headers keep their placeholders, so that the substitution can be
        // made afresh for another attempt
        Map<String, String> appHeaders = new LinkedHashMap<>(attempt.appHeaders);
        List<String> secureStringHeaders = new ArrayList<>();
        for (Map.Entry<String, String> entry : ApproovService.getSubstitutionHeaders().entrySet()) {
            String header = entry.getKey();
            String prefix = entry.getValue();
            String value = header(appHeaders, header);
            if ((value != null) && value.startsWith(prefix) && (value.length() > prefix.length())) {
                // the placeholder is left if the request may not receive secure strings
                if (undelivered != null) {
                    logPlaceholderLeft(undeliveredWarns, "Secure string not substituted in header " + header
                            + ": " + undelivered + ", placeholder left");
                    continue;
                }
                String key = value.substring(prefix.length());
                Approov.TokenFetchResult headerResults = fetchForRequest("fetchSecureStringAndWait",
                        () -> Approov.fetchSecureStringAndWait(key, null));
                ApproovLog.d(TAG, "Substituting header: " + header + ", " + headerResults.getStatus());
                // the request proceeds unless the mutator throws, and a decision to substitute with no value is
                // treated like a decision not to substitute, so the header never carries "null"
                boolean substitute = ApproovService.callMutator("handleRequestHeaderSubstitutionResult",
                        () -> mutator.handleRequestHeaderSubstitutionResult(headerResults, header));
                String secureString = headerResults.getSecureString();
                String failureStatus = failureStatusValue(headerResults);
                if (substitute && (secureString != null)) {
                    if (!ApproovService.isSafeHeaderValue(secureString)) {
                        // a value a header cannot carry leaves the placeholder and is never logged
                        ApproovLog.w(TAG, "Secure string not substituted in header " + header
                                + ": invalid character in value, placeholder left");
                    } else {
                        replaceHeaderValue(appHeaders, header, prefix + secureString);
                        secureStringHeaders.add(header);
                    }
                } else if (failureStatus != null) {
                    // the failure status replaces the placeholder, after any required prefix
                    ApproovLog.d(TAG, "Secure string not substituted in header " + header
                            + ": secure string fetch status " + ApproovService.describeStatus(headerResults)
                            + ", status sent in its place");
                    replaceHeaderValue(appHeaders, header, prefix + failureStatus);
                } else {
                    ApproovLog.d(TAG, "Secure string not substituted in header " + header + ": "
                            + placeholderLeftReason(substitute, headerResults) + ", placeholder left");
                }
            }
        }

        // we now deal with any query parameter substitutions; the query of a redirect target is the server's, so
        // none of its values is looked up or replaced, whatever its parameter names
        String replacementURL = url;
        List<String> queryKeys = new ArrayList<>();
        Map<String, Pattern> substitutionQueryParams = appQuery ? ApproovService.getSubstitutionQueryParams()
                : Collections.<String, Pattern>emptyMap();
        for (Map.Entry<String, Pattern> entry : substitutionQueryParams.entrySet()) {
            String queryKey = entry.getKey();
            Pattern pattern = entry.getValue();
            // every occurrence of the parameter in the query is substituted, each value looked up as its own
            // key, and the search is confined to the query after the first '?' and before any '#'
            int from = replacementURL.indexOf('?');
            while (from >= 0) {
                int hash = replacementURL.indexOf('#', from);
                Matcher matcher = pattern.matcher(replacementURL);
                matcher.region(from, (hash < 0) ? replacementURL.length() : hash);
                if (!matcher.find())
                    break;
                if (undelivered != null) {
                    logPlaceholderLeft(undeliveredWarns, "Secure string not substituted in query parameter "
                            + queryKey + ": " + undelivered + ", placeholder left");
                    break;
                }
                int start = matcher.start(1);
                from = matcher.end(1);
                String queryValue = matcher.group(1);
                Approov.TokenFetchResult queryResults = fetchForRequest("fetchSecureStringAndWait",
                        () -> Approov.fetchSecureStringAndWait(queryValue, null));
                ApproovLog.d(TAG, "Substituting query parameter: " + queryKey + ", " + queryResults.getStatus());
                boolean substitute = ApproovService.callMutator("handleRequestQueryParamSubstitutionResult",
                        () -> mutator.handleRequestQueryParamSubstitutionResult(queryResults, queryKey));
                String secureString = queryResults.getSecureString();
                String failureStatus = failureStatusValue(queryResults);
                if (substitute && (secureString != null)) {
                    if (isCarriedInQuery(secureString)) {
                        if (!queryKeys.contains(queryKey))
                            queryKeys.add(queryKey);
                        replacementURL = new StringBuilder(replacementURL).replace(start, from, secureString)
                                .toString();
                        from = start + secureString.length();
                    } else {
                        // a value the URL cannot carry unchanged leaves the placeholder and is never logged
                        ApproovLog.w(TAG, "Secure string not substituted in query parameter " + queryKey
                                + ": value cannot be carried in the URL, placeholder left");
                    }
                } else if (failureStatus != null) {
                    // the failure status replaces this occurrence of the placeholder
                    ApproovLog.d(TAG, "Secure string not substituted in query parameter " + queryKey
                            + ": secure string fetch status " + ApproovService.describeStatus(queryResults)
                            + ", status sent in its place");
                    replacementURL = new StringBuilder(replacementURL).replace(start, from, failureStatus)
                            .toString();
                    from = start + failureStatus.length();
                } else {
                    ApproovLog.d(TAG, "Secure string not substituted in query parameter " + queryKey + ": "
                            + placeholderLeftReason(substitute, queryResults) + ", placeholder left");
                }
            }
        }

        // the mutations list only the headers and query parameters given a secure string, never a status
        if (!secureStringHeaders.isEmpty())
            changes.setSubstitutionHeaderKeys(secureStringHeaders);
        if (!replacementURL.equals(url) && !queryKeys.isEmpty())
            changes.setSubstitutionQueryParamResults(url, queryKeys);

        // the app's headers as sent, without any the layer sets itself, so that the processed headers hook and
        // any message signature see exactly what is sent
        for (String name : approovHeaders.keySet())
            removeHeader(appHeaders, name);
        ApproovRequestView view = attempt.view.attempt(replacementURL, attempt.view.getMethod(),
                attempt.view.getBody(), appHeaders);

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
     * Gets the value written in place of a placeholder whose secure string fetch failed while the request
     * continues, which is the status name, such as "REJECTED". SUCCESS has none, as it substitutes the
     * secure string. UNKNOWN_KEY has none either: the value is not a secure string key, so it is left as
     * the app wrote it.
     *
     * @param approovResults is the secure string fetch result
     * @return the status to write in place of the placeholder, or null for SUCCESS and UNKNOWN_KEY
     */
    static String failureStatusValue(Approov.TokenFetchResult approovResults) {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        if ((status == Approov.TokenFetchStatus.SUCCESS) || (status == Approov.TokenFetchStatus.UNKNOWN_KEY))
            return null;
        return ApproovService.statusName(approovResults);
    }

    /**
     * Describes why a secure string fetch leaves the placeholder: the value is not a secure string key
     * (UNKNOWN_KEY), the mutator declined a SUCCESS, or it accepted it but the SDK gave no secure string.
     *
     * @param substitute is the decision of the substitution hook
     * @param approovResults is the secure string fetch result
     * @return the reason for the log line
     */
    static String placeholderLeftReason(boolean substitute, Approov.TokenFetchResult approovResults) {
        if (approovResults.getStatus() == Approov.TokenFetchStatus.UNKNOWN_KEY)
            return "value is not a secure string key";
        if (substitute)
            return "no secure string for " + approovResults.getStatus();
        return "secure string fetch status " + ApproovService.describeStatus(approovResults);
    }

    /**
     * Determines why a request whose token fetch returned the given result receives no secure strings,
     * since they are only sent to a token-protected (SUCCESS) or secrets-only (UNPROTECTED_URL) API over
     * TLS.
     *
     * @param url is the request URL
     * @param approovResults is the token fetch result
     * @return the reason including the fetch outcome, or null if secure strings may be substituted
     */
    static String undeliveredReason(String url, Approov.TokenFetchResult approovResults) {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        if (!isHttps(url))
            return "request is not https";
        if ((status == Approov.TokenFetchStatus.SUCCESS) || (status == Approov.TokenFetchStatus.UNPROTECTED_URL))
            return null;
        return "token fetch status " + ApproovService.describeStatus(approovResults);
    }

    /**
     * Determines if a placeholder left for a request is due to a configuration problem that is worth a
     * warning, as the request is not https or the SDK reports its URL as BAD_URL. Any other undelivered
     * secure string is logged at debug level only.
     *
     * @param url is the request URL
     * @param status is the token fetch status
     * @return true if the reason is a configuration problem, false otherwise
     */
    static boolean isConfigurationReason(String url, Approov.TokenFetchStatus status) {
        return !isHttps(url) || (status == Approov.TokenFetchStatus.BAD_URL);
    }

    // determines if a URL is https, comparing the scheme without regard to case
    static boolean isHttps(String url) {
        return (url != null) && url.regionMatches(true, 0, "https:", 0, 6);
    }

    /**
     * Determines if a secure string substituted as a query parameter value reaches the backend unchanged.
     * HttpURLConnection sends the URL as it is given, so the value must be printable ASCII with no space, and
     * neither "&" nor "#", which change the structure of the URL.
     *
     * @param value is the secure string
     * @return true if the URL carries the value unchanged, false otherwise
     */
    static boolean isCarriedInQuery(String value) {
        if (value.isEmpty())
            return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c <= 0x20) || (c > 0x7e) || (c == '&') || (c == '#'))
                return false;
        }
        return true;
    }

    // logs a placeholder left in place, as a warning or at debug level
    static void logPlaceholderLeft(boolean warn, String message) {
        if (warn)
            ApproovLog.w(TAG, message);
        else
            ApproovLog.d(TAG, message);
    }

    /**
     * Logs by name each substitution header and query parameter an attempt carries that is left unchanged
     * because the request may not receive secure strings, as a warning for a configuration problem or at
     * debug level otherwise. A value is never logged.
     *
     * @param attempt is the attempt carrying any placeholders
     * @param reason is why no secure string is delivered, or null if they are
     * @param warn is true if the reason is a configuration problem
     * @param appQuery is true if the query of the attempt URL is the app's own, false if it is a redirect
     * target the server sent, whose query parameters are not placeholders
     */
    private static void logUndeliveredPlaceholders(Attempt attempt, String reason, boolean warn, boolean appQuery) {
        if ((reason == null) || !ApproovLog.isEnabled(warn ? ApproovLogLevel.WARNING : ApproovLogLevel.DEBUG))
            return;

        // log the substitution headers carrying a placeholder
        for (Map.Entry<String, String> entry : ApproovService.getSubstitutionHeaders().entrySet()) {
            String value = header(attempt.appHeaders, entry.getKey());
            if ((value != null) && value.startsWith(entry.getValue()) && (value.length() > entry.getValue().length()))
                logPlaceholderLeft(warn, "Secure string not substituted in header " + entry.getKey() + ": " + reason
                        + ", placeholder left");
        }

        // log the substitution query parameters found in the app's query, after the first '?' and before any '#'
        String url = attempt.url;
        int from = url.indexOf('?');
        if (!appQuery || (from < 0))
            return;
        int hash = url.indexOf('#', from);
        for (Map.Entry<String, Pattern> entry : ApproovService.getSubstitutionQueryParams().entrySet()) {
            Matcher matcher = entry.getValue().matcher(url);
            matcher.region(from, (hash < 0) ? url.length() : hash);
            if (matcher.find())
                logPlaceholderLeft(warn, "Secure string not substituted in query parameter " + entry.getKey() + ": "
                        + reason + ", placeholder left");
        }
    }

    // the lock held while a request sets its token binding value and fetches its token
    private static final Object BINDING_LOCK = new Object();

    /**
     * Fetches the token for an attempt, bound to the value of the token binding header if the request carries
     * it. The SDK holds one binding value for the process, so setting the value and fetching the token are done
     * under a lock, as otherwise two requests on different Volley network dispatcher threads binding different
     * values could each get a token bound to the value of the other. Requests without a binding value fetch
     * concurrently.
     *
     * @param attempt is the attempt, which may carry the binding header
     * @return the fetch result, never null
     * @throws ApproovException if the SDK fails or returns no result
     */
    private static Approov.TokenFetchResult fetchToken(Attempt attempt) throws ApproovException {
        String call = "fetchApproovTokenAndWait";
        String url = attempt.url;
        String bindingHeader = ApproovService.getBindingHeader();
        // header names are case-insensitive; a null value means the header is absent, while a present but
        // empty value is still bound
        String bindingValue = (bindingHeader != null) ? header(attempt.appHeaders, bindingHeader) : null;
        if (bindingValue == null)
            return fetchForRequest(call, () -> Approov.fetchApproovTokenAndWait(url));

        // set the binding value and fetch the token, holding the lock across the two SDK calls only
        Approov.TokenFetchResult approovResults = null;
        RuntimeException bindingFailure = null;
        RuntimeException fetchFailure = null;
        synchronized (BINDING_LOCK) {
            try {
                Approov.setDataHashInToken(bindingValue);
            } catch (RuntimeException e) {
                bindingFailure = e;
            }
            if (bindingFailure == null) {
                try {
                    approovResults = Approov.fetchApproovTokenAndWait(url);
                } catch (RuntimeException e) {
                    fetchFailure = e;
                }
            }
        }

        // report any failure once the lock is released
        if (bindingFailure != null) {
            ApproovService.recordLastARC(null);
            throw ApproovService.sdkFailure("setDataHashInToken", bindingFailure);
        }
        Approov.TokenFetchResult results = approovResults;
        RuntimeException failure = fetchFailure;
        return fetchForRequest(call, () -> {
            if (failure != null)
                throw failure;
            return results;
        });
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
     * Replaces the value of a header, found without regard to the case of its name, keeping the name as it is.
     *
     * @param headers are the headers
     * @param name is the header name
     * @param value is the new value
     */
    static void replaceHeaderValue(Map<String, String> headers, String name, String value) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                entry.setValue(value);
                return;
            }
        }
        headers.put(name, value);
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

    // the redirect status codes HttpURLConnection does not name
    private static final int HTTP_TEMP_REDIRECT = 307;
    private static final int HTTP_PERM_REDIRECT = 308;

    /**
     * Determines if a method permits a request body, which a 300 to 303 redirect turns into a GET without one, as
     * HttpURLConnection does.
     *
     * @param method is the Volley request method
     * @return true if the method permits a body
     */
    static boolean permitsRequestBody(int method) {
        switch (method) {
            case Request.Method.POST:
            case Request.Method.PUT:
            case Request.Method.PATCH:
            case Request.Method.DELETE:
            case Request.Method.OPTIONS:
                return true;
            default:
                return false;
        }
    }

    /**
     * Determines if two URLs reach the same connection, by host and port, so that a redirect between them keeps
     * the Authorization header as HttpURLConnection does. The scheme never changes on a followed redirect.
     *
     * @param a is a URL
     * @param b is another URL
     * @return true if the host and the port are the same
     */
    static boolean sameConnection(URL a, URL b) {
        int portA = (a.getPort() != -1) ? a.getPort() : a.getDefaultPort();
        int portB = (b.getPort() != -1) ? b.getPort() : b.getDefaultPort();
        return a.getHost().equalsIgnoreCase(b.getHost()) && (portA == portB);
    }

    /**
     * Gets the first value of a response header, without regard to the case of its name.
     *
     * @param response is the response
     * @param name is the header name
     * @return the value, or null if the header is absent
     */
    static String responseHeader(HttpResponse response, String name) {
        List<Header> headers = response.getHeaders();
        if (headers == null)
            return null;
        for (Header header : headers) {
            if (name.equalsIgnoreCase(header.getName()))
                return header.getValue();
        }
        return null;
    }

    /**
     * How one network attempt is connected: whether the layer or the platform follows its redirects, and whether
     * Approov pinning applies to it.
     */
    static final class AttemptConnection {
        // true if the layer follows the redirects of the attempt itself
        final boolean followsInLayer;
        // true if Approov pinning applies to the connection
        final boolean pinned;
        // the pinning verifier of the connection, once it is created
        volatile PinningHostnameVerifier verifier;

        AttemptConnection(boolean followsInLayer, boolean pinned) {
            this.followsInLayer = followsInLayer;
            this.pinned = pinned;
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

        /**
         * Gets the attempt that follows a response, if it is a redirect HttpURLConnection follows: 300 to 303
         * for any method, a method that permits a body becoming GET without one, and 307 and 308 for GET and HEAD,
         * to a URL with the same scheme, while HttpURLConnection.getFollowRedirects() is true. The target URL is
         * taken from the Location header as the server sent it, resolved against the attempt URL. The app's own
         * headers and the cache headers go on as the platform sends them: without Authorization on a change of
         * host or port, and without the body headers when the body is dropped.
         *
         * @param response is the response to the attempt
         * @return the next attempt, carrying the app's own headers with their placeholders, or null if the
         * response is not followed
         */
        Attempt redirect(HttpResponse response) {
            if (!HttpURLConnection.getFollowRedirects())
                return null;
            int code = response.getStatusCode();
            int method = view.getMethod();
            boolean toGet;
            switch (code) {
                case HttpURLConnection.HTTP_MULT_CHOICE:
                case HttpURLConnection.HTTP_MOVED_PERM:
                case HttpURLConnection.HTTP_MOVED_TEMP:
                case HttpURLConnection.HTTP_SEE_OTHER:
                    toGet = permitsRequestBody(method);
                    break;
                case HTTP_TEMP_REDIRECT:
                case HTTP_PERM_REDIRECT:
                    // a redirect that must keep the method and body is not followed automatically for any
                    // method but GET and HEAD
                    if ((method != Request.Method.GET) && (method != Request.Method.HEAD))
                        return null;
                    toGet = false;
                    break;
                default:
                    return null;
            }
            String location = responseHeader(response, "Location");
            if (location == null)
                return null;
            URL current;
            URL target;
            try {
                current = new URL(url);
                target = new URL(current, location);
            } catch (MalformedURLException e) {
                return null;
            }
            // as on the platform, a redirect never changes the scheme
            if (!target.getProtocol().equalsIgnoreCase(current.getProtocol()))
                return null;

            Map<String, String> nextHeaders = new LinkedHashMap<>(appHeaders);
            int nextMethod = method;
            byte[] nextBody = view.getBody();
            if (toGet) {
                nextMethod = Request.Method.GET;
                nextBody = null;
                removeHeader(nextHeaders, "Transfer-Encoding");
                removeHeader(nextHeaders, "Content-Length");
                removeHeader(nextHeaders, "Content-Type");
            }
            if (!sameConnection(current, target))
                removeHeader(nextHeaders, "Authorization");
            String nextUrl = target.toString();
            return new Attempt(view.attempt(nextUrl, nextMethod, nextBody, nextHeaders), nextUrl, nextHeaders,
                    cacheHeaders, null);
        }
    }
}
