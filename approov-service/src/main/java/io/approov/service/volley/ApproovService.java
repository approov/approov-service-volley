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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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

    // default header that will carry any optional Approov TraceID debug value
    private static final String APPROOV_TRACE_ID_HEADER = "Approov-TraceID";

    // alternative http stack to be used that adds token and pinning, or null if could not be initialized
    private static ApproovHurlStack hurlStack = null;

    // true if the service layer has been successfully initialized
    private static boolean isInitialized = false;

    // configuration string used for the current initialization
    private static String configString = null;


    // true if the fetch status should be sent as the Approov token header value
    // when a request is allowed to proceed but no real token is available
    private static boolean useApproovStatusIfNoToken = false;

    // header to be used to send Approov tokens
    private static String approovTokenHeader = null;

    // any prefix String to be added before the transmitted Approov token
    private static String approovTokenPrefix = null;

    // header used to send any optional Approov TraceID debug value
    private static String approovTraceIDHeader = null;

    // any binding header for Approov token binding, or null if none
    private static String bindingHeader = null;

    // set of URL regexs that should be excluded from any Approov protection, mapped to the compiled Pattern
    private static Map<String, Pattern> exclusionURLRegexs = null;

    // active mutator for customizing Approov request and result handling
    private static ApproovServiceMutator serviceMutator = ApproovServiceMutator.DEFAULT;


    /**
     * Construction is disallowed as this is a static only class.
     */
    private ApproovService() {
    }

    /**
     * Initializes the ApproovService with an account configuration and comment.
     *
     * @param context the Application context
     * @param config  the configuration string, or empty for no SDK initialization
     * @param comment the comment string, or null for no comment
     */
    public static synchronized void initialize(Context context, String config, String comment) {
        if (config == null)
            throw new IllegalArgumentException("config must not be null; pass \"\" for bypass mode");

        // Initialize the platform SDK if not in bypass mode (empty config).
        // State is only modified after the SDK confirms success, preserving the current
        // operating mode (protected or bypass) if the call fails.
        if (!config.isEmpty()) {
            try {
                boolean sdkInitialized = Approov.initialize(context.getApplicationContext(), config, "auto", comment);
                if (!sdkInitialized) {
                    Log.d(TAG, "Approov SDK already initialized");
                }
            } catch (IllegalArgumentException e) {
                Log.e(TAG, "Approov initialization failed: " + e.getMessage());
                throw e; // service-layer state NOT modified — prior operating mode preserved
            } catch (IllegalStateException e) {
                Log.e(TAG, "Approov initialization failed: " + e.getMessage());
                throw e; // service-layer state NOT modified — prior operating mode preserved
            }
            Approov.setUserProperty("approov-service-volley");
        }
        // SDK succeeded (or bypass) — now reset and commit new service-layer state.
        hurlStack = null;
        isInitialized = false;
        configString = null;
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        approovTraceIDHeader = APPROOV_TRACE_ID_HEADER;
        bindingHeader = null;
        useApproovStatusIfNoToken = false;
        exclusionURLRegexs = new HashMap<>();
        serviceMutator = ApproovServiceMutator.DEFAULT;
        // create an alternative hurlstack to use
        hurlStack = new ApproovHurlStack();
        isInitialized = true;
        configString = config;
    }

    /**
     * Initializes the ApproovService with an account configuration.
     *
     * @param context the Application context
     * @param config the configuration string, or empty for no SDK initialization
     */
    public static void initialize(Context context, String config) {
        // default uses null comment
        initialize(context, config, null);
    }

    /**
     * Sets a flag indicating if the network interceptor should proceed anyway if it is
     * not possible to obtain an Approov token due to a networking failure.
     *
     * @param proceed is true if Approov networking fails should allow continuation
     * @deprecated Use an ApproovServiceMutator to override standard fallback behavior.
     * This method is retained for compatibility but does nothing.
     */
    @Deprecated
    public static synchronized void setProceedOnNetworkFail(boolean proceed) {
        Log.d(TAG, "setProceedOnNetworkFail is deprecated and does nothing.");
    }

    /**
     * @deprecated Always returns false.
     */
    @Deprecated
    static synchronized boolean getProceedOnNetworkFail() {
        return false;
    }

    /**
     * Sets a flag indicating if the Approov fetch status (for example "NO_NETWORK"
     * or "MITM_DETECTED") should be used as the token header value when the
     * request is still allowed to proceed but no real token is available.
     *
     * @param shouldUse true if the fetch status should be used as the token value
     */
    public static synchronized void setUseApproovStatusIfNoToken(boolean shouldUse) {
        Log.d(TAG, "setUseApproovStatusIfNoToken " + shouldUse);
        useApproovStatusIfNoToken = shouldUse;
    }

    /**
     * Gets whether the Approov fetch status should be used as the token header value
     * when no real token is available.
     *
     * @return true if the fetch status should be used as the token value
     */
    public static synchronized boolean getUseApproovStatusIfNoToken() {
        return useApproovStatusIfNoToken;
    }

    /**
     * Indicates whether the service layer has been initialized.
     *
     * @return true if it has been initialized, false otherwise
     */
    public static synchronized boolean isInitialized() {
        return isInitialized;
    }

    /**
     * Indicates whether Approov protection is enabled for this service layer
     * instance. If initialization used an empty config string then the layer is
     * initialized but Approov protection is bypassed.
     *
     * @return true if Approov protection is enabled, false otherwise
     */
    public static synchronized boolean isApproovEnabled() {
        return isInitialized && (configString != null) && !configString.isEmpty();
    }

   /**
     * Sets a development key indicating that the app is a development version and it should
     * pass attestation even if the app is not registered or it is running on an emulator. The
     * development key value can be rotated at any point in the account if a version of the app
     * containing the development key is accidentally released. This is primarily
     * used for situations where the app package must be modified or resigned in
     * some way as part of the testing process.
     *
     * @param devKey is the development key to be used
     * @throws ApproovException if there was a problem
     */
    public static synchronized void setDevKey(String devKey) throws ApproovException {
        try {
            Approov.setDevKey(devKey);
            Log.d(TAG, "setDevKey");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional
     * prefix String (such as "Bearer "). By default the token is provided on
     * "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header
     */
    public static synchronized void setApproovHeader(String header, String prefix) {
        Log.d(TAG, "setApproovHeader " + header + ", " + prefix);
        approovTokenHeader = header;
        approovTokenPrefix = prefix;
    }

    /**
     * Gets the Approov token header.
     *
     * @return header to place the Approov token on
     */
    static synchronized String getApproovHeader() {
        return approovTokenHeader;
    }


    /**
     * Gets the Approov token header value prefix.
     *
     * @return prefix to add to the Approov token header value
     */
    static synchronized String getApproovPrefix() {
        return approovTokenPrefix;
    }

    /**
     * Sets the header name that is used to pass any optional Approov TraceID debug value.
     * Passing null disables the header.
     *
     * @param header is the name of the header on which to place the Approov TraceID, or null to disable it
     */
    public static synchronized void setApproovTraceIDHeader(String header) {
        Log.d(TAG, "setApproovTraceIDHeader " + header);
        approovTraceIDHeader = header;
    }

    /**
     * Gets the header used to hold the optional Approov TraceID.
     *
     * @return the header name used for the Approov TraceID, or null if disabled
     */
    static synchronized String getApproovTraceIDHeader() {
        return approovTraceIDHeader;
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
    public static synchronized void setBindingHeader(String header) {
        Log.d(TAG, "setBindingHeader " + header);
        bindingHeader = header;
    }

    /**
     * Gets any current binding header.
     *
     * @return binding header or null if not set
     */
    static synchronized String getBindingHeader() {
        return bindingHeader;
    }

    /**
     * Sets the active service mutator.
     *
     * @param mutator the mutator to install, or null to restore the default behaviour
     */
    public static synchronized void setServiceMutator(ApproovServiceMutator mutator) {
        if (mutator == null) {
            mutator = ApproovServiceMutator.DEFAULT;
        }
        Log.d(TAG, "Applied ApproovServiceMutator: " + mutator.toString());
        serviceMutator = mutator;
    }

    /**
     * Gets the active service mutator.
     *
     * @return the current service mutator
     */
    public static synchronized ApproovServiceMutator getServiceMutator() {
        return serviceMutator;
    }

    /**
     * Formats a raw value for use on the configured Approov token header.
     *
     * @param value the raw token or fallback value
     * @return the header value, including the configured prefix
     */
    public static synchronized String formatApproovTokenHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        return approovTokenPrefix + value;
    }

    /**
     * Builds the configured Approov token header value from a fetch result.
     *
     * @param approovResults the fetch result to inspect
     * @return the header value, or null if there is no token
     */
    public static synchronized String getApproovTokenHeaderValue(Approov.TokenFetchResult approovResults) {
        if (approovResults == null) {
            return null;
        }
        String token = approovResults.getToken();
        if (token == null || token.isEmpty()) {
            return null;
        }
        return formatApproovTokenHeaderValue(token);
    }

    /**
     * Builds an Approov token header value from a fetch result, falling back to the fetch status when
     * there is no token. This is intended for mutators that choose to proceed with a request after a
     * failed token fetch while still surfacing the specific Approov failure to the backend.
     *
     * @param approovResults the fetch result to inspect
     * @return the header value, or null if neither a token nor a status is available
     */
    public static synchronized String getApproovTokenHeaderValueOrStatus(Approov.TokenFetchResult approovResults) {
        String headerValue = getApproovTokenHeaderValue(approovResults);
        if (headerValue != null) {
            return headerValue;
        }
        if (approovResults == null || approovResults.getStatus() == null) {
            return null;
        }
        return formatApproovTokenHeaderValue(approovResults.getStatus().toString());
    }

    /**
     * Adds an exclusion URL regular expression. If a URL for a request matches this regular expression
     * then it will not be subject to any Approov protection. Note that this facility must be used with
     * EXTREME CAUTION due to the impact of dynamic pinning. Pinning may be applied to all domains added
     * using Approov, and updates to the pins are received when an Approov fetch is performed. If you
     * exclude some URLs on domains that are protected with Approov, then these will be protected with
     * Approov pins but without a path to update the pins until a URL is used that is not excluded. Thus
     * you are responsible for ensuring that there is always a possibility of calling a non-excluded
     * URL, or you should make an explicit call to fetchToken if there are persistent pinning failures.
     * Conversely, use of those option may allow a connection to be established before any dynamic pins
     * have been received via Approov, thus potentially opening the channel to a MitM.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static synchronized void addExclusionURLRegex(String urlRegex) {
        if (hurlStack != null) {
            try {
                Pattern pattern = Pattern.compile(urlRegex);
                exclusionURLRegexs.put(urlRegex, pattern);
                Log.d(TAG, "addExclusionURLRegex " + urlRegex);
            } catch (PatternSyntaxException e) {
                Log.e(TAG, "addExclusionURLRegex " + urlRegex + " error: " + e.getMessage());
            }
        }
    }

    /**
     * Removes an exclusion URL regular expression previously added using addExclusionURLRegex.
     *
     * @param urlRegex is the regular expression that will be compared against URLs to exclude them
     */
    public static synchronized void removeExclusionURLRegex(String urlRegex) {
        if (hurlStack != null) {
            Log.d(TAG, "removeExclusionURLRegex " + urlRegex);
            exclusionURLRegexs.remove(urlRegex);
        }
    }

    /**
     * Gets a copy of the current exclusion URL regexs.
     *
     * @return Map<String, Pattern> of the exclusion regexs to their respective Patterns
     */
    static synchronized Map<String, Pattern> getExclusionURLRegexs() {
        return new HashMap<>(exclusionURLRegexs);
    }

    /**
     * Prefetches in the background to lower the effective latency of a subsequent token fetch or
     * secure string fetch by starting the operation earlier so the subsequent fetch may be able to
     * use cached data.
     */
    public static synchronized void prefetch() {
        if (hurlStack != null)
            // fetch an Approov token using a placeholder domain
            Approov.fetchApproovToken(new PrefetchCallbackHandler(), "approov.io");
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
    public static void precheck() throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "precheck: SDK not initialized");
            throw new ApproovException("precheck: SDK not initialized");
        }
        // try and fetch a non-existent secure string in order to check for a rejection
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchSecureStringAndWait("precheck-dummy-key", null);
            Log.d(TAG, "precheck: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }

        getServiceMutator().handlePrecheckResult(approovResults);
    }

    /**
     * Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note
     * that different Approov apps on the same device will return a different ID. Moreover, the ID may be
     * changed by an uninstall and reinstall of the app.
     *
     * @return String of the device ID
     * @throws ApproovException if there was a problem
     */
    public static String getDeviceID() throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "getDeviceID: SDK not initialized");
            throw new ApproovException("getDeviceID: SDK not initialized");
        }
        try {
            String deviceID = Approov.getDeviceID();
            Log.d(TAG, "getDeviceID: " + deviceID);
            return deviceID;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
    }

    /**
     * Directly sets the data hash to be included in subsequently fetched Approov tokens. If the hash is
     * different from any previously set value then this will cause the next token fetch operation to
     * fetch a new token with the correct payload data hash. The hash appears in the
     * 'pay' claim of the Approov token as a base64 encoded string of the SHA256 hash of the
     * data. Note that the data is hashed locally and never sent to the Approov cloud service.
     *
     * @param data is the data to be hashed and set in the token
     * @throws ApproovException if there was a problem
     */
    public static void setDataHashInToken(String data) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "setDataHashInToken: SDK not initialized");
            throw new ApproovException("setDataHashInToken: SDK not initialized");
        }
        try {
            Approov.setDataHashInToken(data);
            Log.d(TAG, "setDataHashInToken");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Performs an Approov token fetch for the given URL. This should be used in situations where it
     * is not possible to use the networking interception to add the token. This will
     * likely require network access so may take some time to complete. If the attestation fails
     * for any reason then an ApproovException is thrown. This will be ApproovNetworkException for
     * networking issues wher a user initiated retry of the operation should be allowed. Note that
     * the returned token should NEVER be cached by your app, you should call this function when
     * it is needed.
     *
     * @param url is the URL giving the domain for the token fetch
     * @return String of the fetched token
     * @throws ApproovException if there was a problem
     */
    public static String fetchToken(String url) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "fetchToken: SDK not initialized");
            throw new ApproovException("fetchToken: SDK not initialized");
        }
        // fetch the Approov token
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchApproovTokenAndWait(url);
            Log.d(TAG, "fetchToken: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }

        getServiceMutator().handleFetchTokenResult(approovResults);
        return approovResults.getToken();
    }

    /**
     * Gets the signature for the given message. This uses an account specific message signing key that is
     * transmitted to the SDK after a successful fetch if the facility is enabled for the account. Note
     * that if the attestation failed then the signing key provided is actually random so that the
     * signature will be incorrect. An Approov token should always be included in the message
     * being signed and sent alongside this signature to prevent replay attacks. If no signature is
     * available, because there has been no prior fetch or the feature is not enabled, then an
     * ApproovException is thrown.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded message signature
     * @throws ApproovException if there was a problem
     */
    public static String getMessageSignature(String message) throws ApproovException {
        return getAccountMessageSignature(message);
    }

    /**
     * Gets the account message signature for the given message.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded account message signature
     * @throws ApproovException if there was a problem
     */
    public static String getAccountMessageSignature(String message) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "getAccountMessageSignature: SDK not initialized");
            throw new ApproovException("getAccountMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getAccountMessageSignature(message);
            Log.d(TAG, "getAccountMessageSignature");
            if (signature == null)
                throw new ApproovException("no account signature available");
            return signature;
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
    }

    /**
     * Gets the install message signature for the given message.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded install message signature in ASN.1 DER format
     * @throws ApproovException if there was a problem
     */
    public static String getInstallMessageSignature(String message) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "getInstallMessageSignature: SDK not initialized");
            throw new ApproovException("getInstallMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getInstallMessageSignature(message);
            Log.d(TAG, "getInstallMessageSignature");
            if (signature == null)
                throw new ApproovException("no device signature available");
            return signature;
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
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
    public static String fetchSecureString(String key, String newDef) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "fetchSecureString: SDK not initialized");
            throw new ApproovException("fetchSecureString: SDK not initialized");
        }
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
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }

        getServiceMutator().handleFetchSecureStringResult(approovResults, type, key);
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
    public static String fetchCustomJWT(String payload) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "fetchCustomJWT: SDK not initialized");
            throw new ApproovException("fetchCustomJWT: SDK not initialized");
        }
        // fetch the custom JWT catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchCustomJWTAndWait(payload);
            Log.d(TAG, "fetchCustomJWT: " + approovResults.getStatus().toString());
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }

        getServiceMutator().handleFetchCustomJWTResult(approovResults);
        return approovResults.getToken();
    }

    /**
     * Gets the last ARC (Attestation Response Code) code.
     *
     * Always resolves with a string (ARC or empty string).
     * NOTE: You MUST only call this method upon succesfull attestation completion. Any networking
     * errors returned from the service layer will not return a meaningful ARC code if the method is called!!!
     * @return String ARC from last attestation request or empty string if network unavailable
     */
    public static String getLastARC() {
        if (!isApproovEnabled()) {
            Log.e(TAG, "getLastARC: SDK not initialized");
            return "";
        }
        // Get the dynamic pins from Approov
        Map<String, List<String>> approovPins = Approov.getPins("public-key-sha256");
        if (approovPins == null || approovPins.isEmpty()) {
            Log.e(TAG, "ApproovService: no host pinning information available");
            return "";
        }
        // The approovPins contains a map of hostnames to pin strings. Skip '*' and use another hostname if available.
        String hostname = null;
        for (String key : approovPins.keySet()) {
            if (!"*".equals(key)) {
                hostname = key;
                break;
            }
        }
        if (hostname != null) {
            try {
                Approov.TokenFetchResult result = Approov.fetchApproovTokenAndWait(hostname);
                if (result.getToken() != null && !result.getToken().isEmpty()) {
                    String arc = result.getARC();
                    if (arc != null) {
                        return arc;
                    }
                }
                Log.i(TAG, "ApproovService: ARC code unavailable");
                return "";
            } catch (Exception e) {
                Log.e(TAG, "ApproovService: error fetching ARC", e);
                return "";
            }
        } else {
            Log.i(TAG, "ApproovService: ARC code unavailable");
            return "";
        }
    }

    /**
     * Sets an install attributes token to be sent to the server and associated with this particular
     * app installation for future Approov token fetches. The token must be signed, within its
     * expiry time and bound to the correct device ID for it to be accepted by the server.
     * Calling this method ensures that the next call to fetch an Approov
     * token will not use a cached version, so that this information can be transmitted to the server.
     *
     * @param attrs is the signed JWT holding the new install attributes
     * @return void
     * @throws ApproovException if the attrs parameter is invalid or the SDK is not initialized
     */
    public static void setInstallAttrsInToken(String attrs) throws ApproovException {
        if (!isApproovEnabled()) {
            Log.e(TAG, "setInstallAttrsInToken: SDK not initialized");
            throw new ApproovException("setInstallAttrsInToken: SDK not initialized");
        }
        try {
            Approov.setInstallAttrsInToken(attrs);
            Log.d(TAG, "setInstallAttrsInToken");
        } catch (IllegalArgumentException e) {
            Log.e(TAG, "setInstallAttrsInToken failed with IllegalArgument: " + e.getMessage());
            throw new ApproovException("Illegal Argument: " + e.getMessage());
        } catch (IllegalStateException e) {
            Log.e(TAG, "setInstallAttrsInToken failed with IllegalState: " + e.getMessage());
            throw new ApproovException("Illegal State: " + e.getMessage());
        }
    }

    /**
     * Provides the Approov enabled BaseHttpStack to be used for volley. This
     * adds Approov tokens and pinning.
     *
     * @return Approov BaseHttpStack to use, or null if not available
     */
    public static synchronized BaseHttpStack getBaseHttpStack() {
        if (!isApproovEnabled()) {
            return null;
        }
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
     * the output should not be cached. Note that this method does not exclude substitutions made in
     * any added excluded URLs.
     *
     * @param url is the URL for the request
     * @param headers are the defined headers to be updated
     * @param substitutionHeader is the name of any header whose value may be substituted
     * @param requiredPrefix is any required prefix to the value being substituted or null if not required
     * @throws ApproovException if here was a problem
     */
    public static void substituteHeader(String url, Map<String, String> headers, String substitutionHeader,
                                        String requiredPrefix) throws ApproovException {
        if (!isApproovEnabled()) return;
        Approov.TokenFetchResult urlStatus;
        try {
            urlStatus = Approov.fetchApproovTokenAndWait(url);
        } catch (IllegalStateException e) {
            throw new ApproovException(e);
        } catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
        if (urlStatus.getStatus() == Approov.TokenFetchStatus.UNPROTECTED_URL || 
            urlStatus.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL ||
            urlStatus.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
            return;
        }

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
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }

            if (getServiceMutator().handleRequestHeaderSubstitutionResult(approovResults, substitutionHeader))
                // overwrite the request header with the new value
                headers.put(substitutionHeader, prefix + approovResults.getSecureString());
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
     * params values, as the output should not be cached. Note that this method does not exclude
     * substitutions made in any added excluded URLs.
     *
     * @param url is the URL for the request
     * @param params are the defined params to be updated
     * @param queryParam is the name of any parameter whose value may be substituted
     * @throws ApproovException if here was a problem
     */
    public static void substituteQueryParam(String url, Map<String, String> params, String queryParam) throws ApproovException {
        if (!isApproovEnabled()) return;
        Approov.TokenFetchResult urlStatus;
        try {
            urlStatus = Approov.fetchApproovTokenAndWait(url);
        } catch (IllegalStateException e) {
            throw new ApproovException(e);
        } catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
        if (urlStatus.getStatus() == Approov.TokenFetchStatus.UNPROTECTED_URL || 
            urlStatus.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL ||
            urlStatus.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
            return;
        }

        String value = params.get(queryParam);
        if (value != null) {
            // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
            Approov.TokenFetchResult approovResults;
            try {
                approovResults = Approov.fetchSecureStringAndWait(value, null);
                Log.d(TAG, "Substituting query param: " + queryParam + ", " + approovResults.getStatus().toString());
            }
            catch (IllegalStateException e) {
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }

            if (getServiceMutator().handleRequestQueryParamSubstitutionResult(approovResults, queryParam))
                // overwrite the parameter with the new value
                params.put(queryParam, approovResults.getSecureString());
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
     * permanent error condition. Note that this method does not exclude substitutions made in
     * any added excluded URLs.
     *
     * @param url is the URL being analyzed for substitution
     * @param queryParameter is the parameter to be potentially substituted
     * @return URL passed in, or modified with a new URL if required
     * @throws ApproovException if it is not possible to obtain secure strings for substitution
     */
    public static String substituteQueryParamInURLString(String url, String queryParameter) throws ApproovException {
        if (!isApproovEnabled()) return url;
        Approov.TokenFetchResult urlStatus;
        try {
            urlStatus = Approov.fetchApproovTokenAndWait(url);
        } catch (IllegalStateException e) {
            throw new ApproovException(e);
        } catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
        if (urlStatus.getStatus() == Approov.TokenFetchStatus.UNPROTECTED_URL || 
            urlStatus.getStatus() == Approov.TokenFetchStatus.UNKNOWN_URL ||
            urlStatus.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
            return url;
        }

        Pattern pattern = Pattern.compile("[\\?&]"+queryParameter+"=([^&;]+)");
        String urlString = url.toString();
        Matcher matcher = pattern.matcher(urlString);
        if (matcher.find()) {
            // we have found an occurrence of the query parameter to be replaced so we look up the existing
            // value as a key for a secure string
            String queryValue = matcher.group(1);
            Approov.TokenFetchResult approovResults;
            try {
                approovResults = Approov.fetchSecureStringAndWait(queryValue, null);
            }
            catch (IllegalStateException e) {
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }
            Log.d(TAG, "Substituting query parameter: " + queryParameter + ", " + approovResults.getStatus().toString());
            if (getServiceMutator().handleRequestQueryParamSubstitutionResult(approovResults, queryParameter)) {
                // perform a query substitution
                return new StringBuilder(urlString).replace(matcher.start(1),
                            matcher.end(1), approovResults.getSecureString()).toString();
            }
        }
        return url;
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
     * Determines whether a fallback Approov status should be sent in the Approov
     * token header when a request is allowed to continue without a real token.
     */
    private boolean shouldSendFallbackStatusHeader(Approov.TokenFetchResult approovResults) {
        if (!ApproovService.getUseApproovStatusIfNoToken()) {
            return false;
        }

        switch (approovResults.getStatus()) {
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
            case NO_APPROOV_SERVICE:
                return true;
            default:
                return false;
        }
    }

    /**
     * Test seam that allows subclasses to intercept the final network dispatch.
     */
    protected HttpResponse executeNetworkRequest(Request<?> request, Map<String, String> headers)
            throws IOException, AuthFailureError {
        return super.executeRequest(request, headers);
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
        }

        return connection;
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
        
        if (!ApproovService.isApproovEnabled()) {
            return executeNetworkRequest(request, additionalHeaders);
        }

        ApproovServiceMutator mutator = ApproovService.getServiceMutator();
        if (!mutator.handleRequestShouldProcess(request, additionalHeaders)) {
            return executeNetworkRequest(request, additionalHeaders);
        }

        String url = request.getUrl();
        Map<String, String> headers = additionalHeaders == null
                ? new LinkedHashMap<String, String>()
                : new LinkedHashMap<>(additionalHeaders);

        // update the data hash based on any token binding header available from "getHeaders()"
        // on the request (this is the standard way that additional headers are added)
        String bindingHeader = ApproovService.getBindingHeader();
        if (bindingHeader != null) {
            String headerValue = headers.get(bindingHeader);
            if (headerValue == null) {
                Map<String, String> requestHeaders = request.getHeaders();
                if (requestHeaders != null) {
                    headerValue = requestHeaders.get(bindingHeader);
                }
            }
            if (headerValue != null)
                Approov.setDataHashInToken(headerValue);
        }

        // request an Approov token for the domain
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = Approov.fetchApproovTokenAndWait(url);
        }
        catch (IllegalStateException e) {
            throw new ApproovException(e);
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException(e);
        }
        Log.d(TAG, "Token for " + request.getUrl() + ": " + approovResults.getLoggableToken());

        boolean continueWithFullProcessing = mutator.handleRequestFetchTokenResult(approovResults, url);
        ApproovRequestMutations changes = new ApproovRequestMutations();
        String tokenHeaderValue = null;
        if (continueWithFullProcessing) {
            tokenHeaderValue = mutator.handleRequestTokenHeaderValue(approovResults, url);
        } else if (shouldSendFallbackStatusHeader(approovResults)) {
            tokenHeaderValue = ApproovService.getApproovTokenHeaderValueOrStatus(approovResults);
            Log.d(TAG, "Proceeding with fallback token header " + ApproovService.getApproovHeader()
                    + ": " + tokenHeaderValue);
        } else {
            return executeNetworkRequest(request, headers);
        }

        if (tokenHeaderValue != null) {
            String tokenHeader = ApproovService.getApproovHeader();
            headers.put(tokenHeader, tokenHeaderValue);
            changes.setTokenHeaderKey(tokenHeader);
        }

        String traceIDHeader = ApproovService.getApproovTraceIDHeader();
        String traceID = approovResults.getTraceID();
        if (traceIDHeader != null && traceID != null && !traceID.isEmpty()) {
            headers.put(traceIDHeader, traceID);
            changes.setTraceIDHeaderKey(traceIDHeader);
        }

        headers = mutator.handleRequestProcessedHeaders(request, headers, changes);
        if (headers == null) {
            headers = new LinkedHashMap<>();
        }

        // delegate the execution of the request to the parent handler
        return executeNetworkRequest(request, headers);
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
