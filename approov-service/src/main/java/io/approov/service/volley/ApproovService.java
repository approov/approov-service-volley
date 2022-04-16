//
// MIT License
// 
// Copyright (c) 2016-present, Critical Blue Ltd.
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

import android.util.Log;
import android.content.Context;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.toolbox.BaseHttpStack;
import com.android.volley.toolbox.HttpResponse;
import com.android.volley.toolbox.HurlStack;
import com.criticalblue.approovsdk.Approov;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import okio.ByteString;

// ApproovService provides a mediation layer to the Approov SDK itself
public class ApproovService {
    // logging tag
    private static final String TAG = "ApproovService";

    // default header that will be added to Approov enabled requests
    private static final String APPROOV_TOKEN_HEADER = "Approov-Token";

    // default  prefix to be added before the Approov token by default
    private static final String APPROOV_TOKEN_PREFIX = "";

    // alternative http stack to be used that adds token and pinning, or null if could not be initialized
    private ApproovHurlStack hurlStack;

    // true if the interceptor should proceed on network failures and not add an
    // Approov token
    private boolean proceedOnNetworkFail;

    // header to be used to send Approov tokens
    private String approovTokenHeader;

    // any prefix String to be added before the transmitted Approov token
    private String approovTokenPrefix;

    // any binding header for Approov token binding, or null if none
    private String bindingHeader;

    /**
     * Creates an Approov service.
     *
     * @param context the Application context
     * @param config the initial service config string, or empty for no initialization
     */
    public ApproovService(Context context, String config) {
        // initialize the Approov SDK
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        bindingHeader = null;
        proceedOnNetworkFail = false;
        try {
            if (config.length() != 0)
                Approov.initialize(context, config, "auto", null);
            Approov.setUserProperty("approov-service-volley");
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Approov initialization failed: " + e.getMessage());
            return;
        }

        // create an alternative hurlstack to use
        hurlStack = new ApproovHurlStack(this);
    }

    /**
     * Sets a flag indicating if the network interceptor should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure. If this is set
     * then your backend API can receive calls without the expected Approov token header
     * being added, or without header/query parameter substitutions being made.
     *
     * @param proceed is true if Approov networking fails should allow continuation
     */
    public synchronized void setProceedOnNetworkFail(boolean proceed) {
        proceedOnNetworkFail = proceed;
    }

    /**
     * Gtes the flag indicating if the network interceptor should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure.
     *
     * @return true if Approov networking fails should allow continuation
     */
    synchronized boolean getProceedOnNetworkFail() {
        return proceedOnNetworkFail;
    }

    /**
     * Prefetches in the background to lower the effective latency of a subsequent token fetch or
     * secure string fetch by starting the operation earlier so the subsequent fetch may be able to
     * use cached data.
     */
    public synchronized void prefetch() {
        if (hurlStack != null)
            // fetch an Approov token using a placeholder domain
            Approov.fetchApproovToken(new PrefetchCallbackHandler(), "www.approov.io");
    }

    // Performs a precheck to determine if the app will pass attestation. This requires secure
    // strings to be enabled for the account, although no strings need to be set up. This will
    // likely require network access so may take some time to complete. It may throw ApproovException
    // if the precheck fails or if there is some other problem. ApproovRejectionException is thrown
    // if the app has failed Approov checks or ApproovNetworkException for networking issues where a
    // user initiated retry of the operation should be allowed. An ApproovRejectionException may provide
    // additional information about the cause of the rejection.
    //
    // @throws ApproovException if there was a problem
    public void precheck() throws ApproovException {
        // try and fetch a non-existent secure string in order to check for a rejection
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", null);
            Log.d(TAG, "precheck: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status
        if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
            // if the request is rejected then we provide a special exception with additional information
            throw new ApproovRejectionException("precheck: " + approovResults.getStatus().toString() + ": " +
                    approovResults.getARC() + " " + approovResults.getRejectionReasons(),
                    approovResults.getARC(), approovResults.getRejectionReasons());
        else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw new ApproovNetworkException("precheck: " + approovResults.getStatus().toString());
        else if ((approovResults.getStatus() != Approov.TokenFetchStatus.SUCCESS) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_KEY))
            // we are unable to get the secure string due to a more permanent error
            throw new ApproovException("precheck:" + approovResults.getStatus().toString());
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional
     * prefix String (such as "Bearer "). By default the token is provided on
     * "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header
     */
    public synchronized void setApproovHeader(String header, String prefix) {
        approovTokenHeader = header;
        approovTokenPrefix = prefix;
    }

    /**
     * Gets the Approov token header.
     *
     * @return header to place the Approov token on
     */
    synchronized String getApproovHeader() {
        return approovTokenHeader;
    }


    /**
     * Gets the Approov token header value prefix.
     *
     * @return prefix to add to the Approov token header value
     */
    synchronized String getApproovPrefix() {
        return approovTokenPrefix;
    }

    /**
     * Sets a binding header that must be present on all requests using the Approov service. A
     * header should be chosen whose value is unchanging for most requests (such as an
     * Authorization header). A hash of the header value is included in the issued Approov tokens
     * to bind them to the value. This may then be verified by the backend API integration. This
     * method should typically only be called once.
     *
     * @param header is the header to use for Approov token binding
     */
    public synchronized void setBindingHeader(String header) {
        bindingHeader = header;
    }

    /**
     * Gets any current binding header.
     *
     * @return binding header or null if not set
     */
    synchronized String getBindingHeader() {
        return bindingHeader;
    }

    /**
     * Provides the Approov enabled BaseHttpStack to be used for volley. This
     * adds Approov tokens and pinning.
     *
     * @return Approov BaseHttpStack to use, or null if not available
     */
    public synchronized BaseHttpStack getBaseHttpStack() {
        return hurlStack;
    }

    /**
     * Potentially substitutes a header value in the map supplied. This determines if the given
     * substitution header is present and, if so, looks at the present value and determines if it
     * corresponds to a key of a secure string. If so then the header value is remapped to the secure
     * string value. A required prefix may be specified to deal with cases such as the use of
     * "Bearer " prefixed before values in an authorization header. If the attestation fails for
     * any reason then an ApproovException is thrown. This will be ApproovRejectionException if
     * the app has failed Approov checks or ApproovNetworkException for networking issues where a
     * user initiated retry of the operation should be allowed. Note that this function should only
     * be called by a request getHeaders function that provides the ephemeral header values, as
     * the output should not be cached.
     *
     * @param headers are the defined headers to be updated
     * @param substitutionHeader is the name of any header whose value may be substituted
     * @param requiredPrefix is any required prefix to the value being substituted or null if not required
     * @throws ApproovException if here was a problem
     */
    public static void substituteHeader(Map<String, String> headers, String substitutionHeader,
                                        String requiredPrefix) throws ApproovException {
        String prefix = requiredPrefix;
        if (prefix == null)
            prefix = "";
        String value = headers.get(substitutionHeader);
        if ((value != null) && value.startsWith(prefix) && (value.length() > prefix.length())) {
            // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
            Approov.TokenFetchResult approovResults;
            try {
                approovResults = Approov.fetchSecureStringAndWait(value.substring(prefix.length()), null);
                Log.d(TAG, "Substituting header: " + substitutionHeader + ", " + approovResults.getStatus().toString());
            }
            catch (IllegalStateException e) {
                throw new ApproovException("IllegalState: " + e.getMessage());
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException("IllegalArgument: " + e.getMessage());
            }

            // process the returned Approov status
            if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS)
                // overwrite the request header with the new value
                headers.put(substitutionHeader, prefix + approovResults.getSecureString());
            else if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
                // if the request is rejected then we provide a special exception with additional information
                throw new ApproovRejectionException("Header substitution for " + substitutionHeader + ": " +
                        approovResults.getStatus().toString() + ": " + approovResults.getARC() +
                        " " + approovResults.getRejectionReasons(),
                        approovResults.getARC(), approovResults.getRejectionReasons());
            else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
                // we are unable to get the secure string due to network conditions so the request can
                // be retried by the user later
                throw new ApproovNetworkException("Header substitution for " + substitutionHeader + ": " +
                        approovResults.getStatus().toString());
            else if (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_KEY)
                // we have failed to get a secure string with a more serious permanent error
                throw new ApproovException("Header substitution for " + substitutionHeader + ": " +
                        approovResults.getStatus().toString());
        }
    }

    /**
     * Potentially substitutes a parameter value in the map supplied. This determines if the given
     * substitution query parameter is present and, if so, looks at the present value and determines if it
     * corresponds to a key of a secure string. If so then the parameter value is remapped to the secure
     * string value. If the attestation fails for any reason then an ApproovException is thrown. This
     * will be ApproovRejectionException if the app has failed Approov checks or ApproovNetworkException
     * for networking issues where a user initiated retry of the operation should be allowed. Note that
     * this function should only be called by a request getParams function that provides the ephemeral
     * params values, as the output should not be cached.
     *
     * @param params are the defined params to be updated
     * @param queryParam is the name of any parameter whose value may be substituted
     * @throws ApproovException if here was a problem
     */
    public static void substituteQueryParam(Map<String, String> params, String queryParam) throws ApproovException {
        String value = params.get(queryParam);
        if (value != null) {
            // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
            Approov.TokenFetchResult approovResults;
            try {
                approovResults = Approov.fetchSecureStringAndWait(value, null);
                Log.d(TAG, "Substituting query param: " + queryParam + ", " + approovResults.getStatus().toString());
            }
            catch (IllegalStateException e) {
                throw new ApproovException("IllegalState: " + e.getMessage());
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException("IllegalArgument: " + e.getMessage());
            }

            // process the returned Approov status
            if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS)
                // overwrite the parameter with the new value
                params.put(queryParam, approovResults.getSecureString());
            else if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
                // if the request is rejected then we provide a special exception with additional information
                throw new ApproovRejectionException("Query param substitution for " + queryParam + ": " +
                        approovResults.getStatus().toString() + ": " + approovResults.getARC() +
                        " " + approovResults.getRejectionReasons(),
                        approovResults.getARC(), approovResults.getRejectionReasons());
            else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
                // we are unable to get the secure string due to network conditions so the request can
                // be retried by the user later
                throw new ApproovNetworkException("Query param substitution for " + queryParam + ": " +
                        approovResults.getStatus().toString());
            else if (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_KEY)
                // we have failed to get a secure string with a more serious permanent error
                throw new ApproovException("Query param substitution for " + queryParam + ": " +
                        approovResults.getStatus().toString());
        }
    }

    /**
     * Substitutes the given query parameter in the URL. If no substitution is made then the
     * original URL is returned, otherwise a new one is constructed with the revised query
     * parameter value. Since this modifies the URL itself this must be done before opening the
     * HttpsURLConnection. If it is not currently possible to fetch secure strings token due to
     * networking issues then ApproovNetworkException is thrown and a user initiated retry of the
     * operation should be allowed. ApproovRejectionException may be thrown if the attestation
     * fails and secure strings cannot be obtained. Other ApproovExecptions represent a more
     * permanent error condition.
     *
     * @param url is the URL being analyzed for substitution
     * @param queryParameter is the parameter to be potentially substituted
     * @return URL passed in, or modified with a new URL if required
     * @throws ApproovException if it is not possible to obtain secure strings for substitution
     */
    public static String substituteQueryParamInURLString(String url, String queryParameter) throws ApproovException {
        Pattern pattern = Pattern.compile("[\\?&]"+queryParameter+"=([^&;]+)");
        String urlString = url.toString();
        Matcher matcher = pattern.matcher(urlString);
        if (matcher.find()) {
            // we have found an occurrence of the query parameter to be replaced so we look up the existing
            // value as a key for a secure string
            String queryValue = matcher.group(1);
            Approov.TokenFetchResult approovResults = Approov.fetchSecureStringAndWait(queryValue, null);
            Log.d(TAG, "Substituting query parameter: " + queryParameter + ", " + approovResults.getStatus().toString());
            if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS) {
                // perform a query substitution
                return new StringBuilder(urlString).replace(matcher.start(1),
                            matcher.end(1), approovResults.getSecureString()).toString();
            }
            else if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
                // if the request is rejected then we provide a special exception with additional information
                throw new ApproovRejectionException("Query parameter substitution for " + queryParameter + ": " +
                        approovResults.getStatus().toString() + ": " + approovResults.getARC() +
                        " " + approovResults.getRejectionReasons(),
                        approovResults.getARC(), approovResults.getRejectionReasons());
            else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                    (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
                // we are unable to get the secure string due to network conditions so the request can
                // be retried by the user later
                throw new ApproovNetworkException("Query parameter substitution for " + queryParameter + ": " +
                            approovResults.getStatus().toString());
            else if (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_KEY)
                // we have failed to get a secure string with a more serious permanent error
                throw new ApproovException("Query parameter substitution for " + queryParameter + ": " +
                        approovResults.getStatus().toString());
        }
        return url;
    }

    /**
     * Fetches a secure string with the given key. If newDef is not null then a
     * secure string for the particular app instance may be defined. In this case the
     * new value is returned as the secure string. Use of an empty string for newDef removes
     * the string entry. Note that this call may require network transaction and thus may block
     * for some time, so should not be called from the UI thread. If the attestation fails
     * for any reason then an ApproovException is thrown. This will be ApproovRejectionException
     * if the app has failed Approov checks or ApproovNetworkException for networking issues where
     * a user initiated retry of the operation should be allowed. Note that the returned string
     * should NEVER be cached by your app, you should call this function when it is needed.
     *
     * @param key is the secure string key to be looked up
     * @param newDef is any new definition for the secure string, or null for lookup only
     * @return secure string (should not be cached by your app) or null if it was not defined
     * @throws ApproovException if there was a problem
     */
    public String fetchSecureString(String key, String newDef) throws ApproovException {
        // determine the type of operation as the values themselves cannot be logged
        String type = "lookup";
        if (newDef != null)
            type = "definition";

        // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchSecureStringAndWait(key, newDef);
            Log.d(TAG, "fetchSecureString " + type + ": " + key + ", " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
                throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status
        if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
            // if the request is rejected then we provide a special exception with additional information
            throw new ApproovRejectionException("fetchSecureString " + type + " for " + key + ": " +
                    approovResults.getStatus().toString() + ": " + approovResults.getARC() +
                    " " + approovResults.getRejectionReasons(),
                    approovResults.getARC(), approovResults.getRejectionReasons());
        else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
            // we are unable to get the secure string due to network conditions so the request can
            // be retried by the user later
            throw new ApproovNetworkException("fetchSecureString " + type + " for " + key + ":" +
                    approovResults.getStatus().toString());
        else if ((approovResults.getStatus() != Approov.TokenFetchStatus.SUCCESS) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_KEY))
            // we are unable to get the secure string due to a more permanent error
            throw new ApproovException("fetchSecureString " + type + " for " + key + ":" +
                    approovResults.getStatus().toString());
        return approovResults.getSecureString();
    }

    /**
     * Fetches a custom JWT with the given payload. Note that this call will require network
     * transaction and thus will block for some time, so should not be called from the UI thread.
     * If the attestation fails for any reason then an IOException is thrown. This will be
     * ApproovRejectionException if the app has failed Approov checks or ApproovNetworkException
     * for networking issues where a user initiated retry of the operation should be allowed.
     *
     * @param payload is the marshaled JSON object for the claims to be included
     * @return custom JWT string
     * @throws ApproovException if there was a problem
     */
    public String fetchCustomJWT(String payload) throws ApproovException {
        // fetch the custom JWT catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchCustomJWTAndWait(payload);
            Log.d(TAG, "fetchCustomJWT: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }

        // process the returned Approov status
        if (approovResults.getStatus() == Approov.TokenFetchStatus.REJECTED)
            // if the request is rejected then we provide a special exception with additional information
            throw new ApproovRejectionException("fetchCustomJWT: "+ approovResults.getStatus().toString() + ": " +
                    approovResults.getARC() +  " " + approovResults.getRejectionReasons(),
                    approovResults.getARC(), approovResults.getRejectionReasons());
        else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
            // we are unable to get the custom JWT due to network conditions so the request can
            // be retried by the user later
            throw new ApproovNetworkException("fetchCustomJWT: " + approovResults.getStatus().toString());
        else if (approovResults.getStatus() != Approov.TokenFetchStatus.SUCCESS)
            // we are unable to get the custom JWT due to a more permanent error
            throw new ApproovException("fetchCustomJWT: " + approovResults.getStatus().toString());
        return approovResults.getToken();
    }
}

/**
 * Callback handler for prefetching from Approov. We simply log as we don't need the result
 * itself, as it will be returned as a cached value on a subsequent etch.
 */
final class PrefetchCallbackHandler implements Approov.TokenFetchCallback {
    // logging tag
    private static final String TAG = "ApproovPrefetch";

    @Override
    public void approovCallback(Approov.TokenFetchResult pResult) {
        if (pResult.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL)
            Log.d(TAG, "Approov prefetch success");
        else
            Log.e(TAG, "Approov prefetch failure: " + pResult.getStatus().toString());
    }
}

/**
 * Alternative HurlStack to be used for Approov that adds Approov tokens and pinning. This
 * overrides certain methods in the default stack to provide this functionality. The pinning
 * approach used is immediately reactive to pinning changes.
 */
final class ApproovHurlStack extends HurlStack {
    // logging tag
    private static final String TAG = "ApproovHurlStack";

    // underlying ApproovService being utilized
    private ApproovService approovService;

    /**
     * Constructs an new HurlStack that adds Approov tokens and pinning.
     *
     * @param service is the underlying ApproovService being used
     */
    public ApproovHurlStack(ApproovService service) {
        super();
        approovService = service;
    }

    /**
     * Adds pinning to the connection by overriding the HostnameVerifier with something that pins
     * the connections. The connection must be for https.
     */
    @Override
    protected HttpURLConnection createConnection(URL url) throws IOException {
        // ensure the connection is pinned (note we assume a https connection here)
        PinningHostnameVerifier pinningHostnameVerifier = new PinningHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
        urlConnection.setHostnameVerifier(pinningHostnameVerifier);

        // Workaround for the M release HttpURLConnection not observing the
        // HttpURLConnection.setFollowRedirects() property.
        // https://code.google.com/p/android/issues/detail?id=194495
        urlConnection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());

        // provide the created connection
        return urlConnection;
    }

    /**
     * Adds Approov token for the given request The Approov token is added in a header. If a
     * binding header has been specified then this should be available. If it is not
     * currently possible to fetch an Approov token (typically due to no or poor network) then
     * an exception is thrown and a later retry should be made.
     */
    @Override
    public HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders)
            throws IOException, AuthFailureError {
        // we don't modify the headers by default
        Map<String, String> headers = additionalHeaders;

        // update the data hash based on any token binding header available from "getHeaders()"
        // on the request (this is the standard way that additional headers are added)
        String bindingHeader = approovService.getBindingHeader();
        if (bindingHeader != null) {
            String headerValue = request.getHeaders().get(bindingHeader);
            if (headerValue != null)
                Approov.setDataHashInToken(headerValue);
        }

        // request an Approov token for the domain
        String url = request.getUrl();
        Approov.TokenFetchResult approovResults = Approov.fetchApproovTokenAndWait(url);

        // provide information about the obtained token or error (note "approov token -check" can
        // be used to check the validity of the token and if you use token annotations they
        // will appear here to determine why a request is being rejected)
        Log.d(TAG, "Token for " + request.getUrl() + ": " + approovResults.getLoggableToken());

        // check the status of Approov token fetch
        if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS) {
            // we successfully obtained a token so add it to the header for the request - we have
            // to copy the header map since we cannot modify the parameter
            headers = new HashMap<>(additionalHeaders);
            headers.put(approovService.getApproovHeader(), approovService.getApproovPrefix() + approovResults.getToken());
        }
        else if ((approovResults.getStatus() == Approov.TokenFetchStatus.NO_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.POOR_NETWORK) ||
                (approovResults.getStatus() == Approov.TokenFetchStatus.MITM_DETECTED))
            // we are unable to get an Approov token due to network conditions so the request can
            // be retried by the user later - unless overridden
            if (!approovService.getProceedOnNetworkFail())
                throw new ApproovNetworkException("Approov token fetch for " + url + " failed: " + approovResults.getStatus().toString());
        else if ((approovResults.getStatus() != Approov.TokenFetchStatus.NO_APPROOV_SERVICE) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_URL) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNPROTECTED_URL)) {
            // we have failed to get an Approov token with a more serious permanent error
            throw new ApproovException("Approov token fetch for " + url + " failed: " + approovResults.getStatus().toString());
        }

        // delegate the execution of the request to the parent handler
        return super.executeRequest(request, headers);
    }
}

/**
 * Performs pinning for use with HttpsUrlConnection. This implementation of HostnameVerifier is
 * intended to enhance the HostnameVerifier your TLS implementation normally uses. The
 * HostnameVerifier passed into the constructor continues to be executed when verify is called. The
 * is only applied if the usual HostnameVerifier first passes (so this implementation can only be
 * more secure). This pins to the SHA256 of the public key hash of any certificate in the trust
 * chain for the host (so technically this is public key rather than certificate pinning). Note that
 * this uses the current live Approov pins so is immediately updated if there is a configuration
 * update to the app.
 */
final class PinningHostnameVerifier implements HostnameVerifier {
    // Tag for log messages
    private static final String TAG = "ApproovPinVerifier";

    // HostnameVerifier you would normally be using
    private final HostnameVerifier delegate;

    /**
     * Construct a PinningHostnameVerifier which delegates
     * the initial verify to a user defined HostnameVerifier before
     * applying pinning on top.
     *
     * @param delegate is the HostnameVerifier to apply before the custom pinning
     */
    public PinningHostnameVerifier(HostnameVerifier delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // check the delegate function first and only proceed if it passes
        if (delegate.verify(hostname, session)) try {
            // extract the set of valid pins for the hostname
            Set<String> hostPins = new HashSet<>();
            Map<String, List<String>> allPins = Approov.getPins("public-key-sha256");
            List<String> pins = allPins.get(hostname);
            if ((pins != null) && pins.isEmpty())
                // if there are no pins associated with the hostname domain then we use any pins
                // associated with the "*" domain for managed trust roots (note we do not
                // apply this to domains that are not added at all)
                pins = allPins.get("*");
            if (pins != null) {
                // convert the list of pins into a set
                for (String pin: pins)
                    hostPins.add(pin);
            }

            // if there are no pins then we accept any certificate
            if (hostPins.isEmpty())
                return true;

            // check to see if any of the pins are in the certificate chain
            for (Certificate cert: session.getPeerCertificates()) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    ByteString digest = ByteString.of(x509Cert.getPublicKey().getEncoded()).sha256();
                    String hash = digest.base64();
                    if (hostPins.contains(hash))
                        return true;
                }
                else
                    Log.e(TAG, "Certificate not X.509");
            }

            // the connection is rejected
            Log.w(TAG, "Pinning rejection for " + hostname);
            return false;
        } catch (SSLException e) {
            Log.e(TAG, "Delegate Exception");
            throw new RuntimeException(e);
        }
        return false;
    }
}
