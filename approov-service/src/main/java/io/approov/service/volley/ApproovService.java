// ApproovService for integrating Approov into apps using Volley.
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

import android.content.SharedPreferences;
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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import okio.ByteString;

// ApproovService provides a mediation layer to the Approov SDK itself
public class ApproovService {
    // logging tag
    private static final String TAG = "ApproovService";

    // keys for the Approov shared preferences
    private static final String APPROOV_CONFIG = "approov-config";
    private static final String APPROOV_PREFS = "approov-prefs";

    // default header that will be added to Approov enabled requests
    private static final String APPROOV_TOKEN_HEADER = "Approov-Token";

    // default  prefix to be added before the Approov token by default
    private static final String APPROOV_TOKEN_PREFIX = "";

    // context for handling preferences
    private Context appContext;

    // alternative http stack to be used that adds token and pinning, or null if could not be initialized
    private ApproovHurlStack hurlStack;

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
     * @param config the initial service config string
     */
    public ApproovService(Context context, String config) {
        // initialize the Approov SDK
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        bindingHeader = null;
        appContext = context;
        String dynamicConfig = getApproovDynamicConfig();
        try {
            Approov.initialize(context, config, dynamicConfig, null);
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "Approov initialization failed: " + e.getMessage());
            return;
        }

        // create an alternative hurlstack to use
        hurlStack = new ApproovHurlStack(this);

        // if we didn't have a dynamic configuration (after the first launch on the app) then
        // we fetch the latest and write it to local storage now
        if (dynamicConfig == null)
            updateDynamicConfig();
    }

    /**
     * Prefetches an Approov token in the background. The placeholder domain "www.approov.io" is
     * simply used to initiate the fetch and does not need to be a valid API for the account. This
     * method can be used to lower the effective latency of a subsequent token fetch by starting
     * the operation earlier so the subsequent fetch may be able to use a cached token.
     */
    public synchronized void prefetchApproovToken() {
        if (hurlStack != null)
            Approov.fetchApproovToken(new PrefetchCallbackHandler(), "www.approov.io");
    }

    /**
     * Writes the latest dynamic configuration that the Approov SDK has.
     */
    public synchronized void updateDynamicConfig() {
        Log.i(TAG, "Approov dynamic configuration updated");
        putApproovDynamicConfig(Approov.fetchConfig());
    }

    /**
     * Stores an application's dynamic configuration string in non-volatile storage.
     *
     * The default implementation stores the string in shared preferences, and setting
     * the config string to null is equivalent to removing the config.
     *
     * @param config a config string
     */
    protected void putApproovDynamicConfig(String config) {
        SharedPreferences prefs = appContext.getSharedPreferences(APPROOV_PREFS, 0);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(APPROOV_CONFIG, config);
        editor.apply();
    }

    /**
     * Returns the application's dynamic configuration string from non-volatile storage.
     *
     * The default implementation retrieves the string from shared preferences.
     *
     * @return config string, or null if not present
     */
    protected String getApproovDynamicConfig() {
        SharedPreferences prefs = appContext.getSharedPreferences(APPROOV_PREFS, 0);
        return prefs.getString(APPROOV_CONFIG, null);
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
}

/**
 * Callback handler for prefetching an Approov token. We simply log as we don't need the token
 * itself, as it will be returned as a cached value on a subsequent token fetch.
 */
final class PrefetchCallbackHandler implements Approov.TokenFetchCallback {
    // logging tag
    private static final String TAG = "ApproovPrefetch";

    @Override
    public void approovCallback(Approov.TokenFetchResult pResult) {
        if (pResult.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL)
            Log.i(TAG, "Approov prefetch success");
        else
            Log.i(TAG, "Approov prefetch failure: " + pResult.getStatus().toString());
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
        // we don't modify the map by default
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
        Approov.TokenFetchResult approovResults = Approov.fetchApproovTokenAndWait(request.getUrl());

        // provide information about the obtained token or error (note "approov token -check" can
        // be used to check the validity of the token and if you use token annotations they
        // will appear here to determine why a request is being rejected)
        Log.i(TAG, "Approov Token for " + request.getUrl() + ": " + approovResults.getLoggableToken());

        // update any dynamic configuration
        if (approovResults.isConfigChanged())
            approovService.updateDynamicConfig();

        // check the status of Approov token fetch
        if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS) {
            // we successfully obtained a token so add it to the header for the request - we have
            // to copy the header map since we cannot modify the parameter
            headers = new HashMap<>(additionalHeaders);
            headers.put(approovService.getApproovHeader(), approovService.getApproovPrefix() + approovResults.getToken());
        }
        else if ((approovResults.getStatus() != Approov.TokenFetchStatus.NO_APPROOV_SERVICE) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNKNOWN_URL) &&
                (approovResults.getStatus() != Approov.TokenFetchStatus.UNPROTECTED_URL)) {
            // we have failed to get an Approov token in such a way that there is no point in proceeding
            // with the request - generally a retry is needed, unless the error is permanent
            throw new IOException("Approov token fetch failed: " + approovResults.getStatus().toString());
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
            Map<String, List<String>> pins = Approov.getPins("public-key-sha256");
            for (Map.Entry<String, List<String>> entry: pins.entrySet()) {
                if (entry.getKey().equals(hostname)) {
                    for (String pin: entry.getValue())
                        hostPins.add(pin);
                }
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
