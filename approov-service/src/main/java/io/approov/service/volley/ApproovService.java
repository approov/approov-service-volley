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

import android.content.Context;

import androidx.annotation.VisibleForTesting;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.toolbox.BaseHttpStack;
import com.android.volley.toolbox.HttpResponse;
import com.android.volley.toolbox.HurlStack;
import com.criticalblue.approovsdk.Approov;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.PatternSyntaxException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import android.util.Base64;

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

    // true if the service layer has been successfully initialized, bypass mode included
    private static boolean isInitialized = false;

    // true if the Approov SDK has been initialized by this layer with a non-empty account ID. The account ID
    // is not kept, as the SDK is the only judge of a repeat call.
    private static boolean approovProtectionEnabled = false;

    // the ARC of the most recent token, secure string or custom JWT fetch, or empty
    private static String lastARC = "";

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
     * Converts a RuntimeException thrown by an Approov SDK call on the request path into an ApproovException
     * with it as the cause, logged at error level, so that the request fails through the normal Volley error
     * handling.
     *
     * @param call is the name of the SDK method that threw, for the log
     * @param e is the exception thrown by the SDK
     * @return the exception to throw
     */
    static ApproovException sdkFailure(String call, RuntimeException e) {
        ApproovException wrapped = new ApproovException(e);
        ApproovLog.e(TAG, call + ": " + wrapped.getMessage());
        return wrapped;
    }

    /**
     * Reports an Approov SDK fetch that returned no result, logged at error level.
     *
     * @param call is the name of the SDK method, for the log and the exception message
     * @return the exception to throw
     */
    static ApproovException sdkNoResult(String call) {
        String message = "Approov SDK " + call + " returned no result";
        ApproovLog.e(TAG, message);
        return new ApproovException(message);
    }

    // a call into the installed service mutator
    interface MutatorHook<T> {
        T call() throws ApproovException;
    }

    // the exceptions raised by the standard request decisions during the mutator hook call in progress on
    // this thread, or null outside a hook call
    private static final ThreadLocal<Set<Throwable>> standardDecisions = new ThreadLocal<>();

    /**
     * Records an exception raised by a standard request decision (the interface defaults of
     * ApproovServiceMutator, which CLOSE_FAILURE uses) during the hook call in progress on this thread,
     * so that callMutator passes it through unchanged whether the installed mutator inherited or called
     * the decision. Outside a hook call it only returns the exception.
     *
     * @param e is the exception the decision raises
     * @return the exception, to be thrown
     */
    static <E extends ApproovException> E standardDecision(E e) {
        Set<Throwable> made = standardDecisions.get();
        if (made != null)
            made.add(e);
        return e;
    }

    /**
     * Calls a hook of the installed service mutator on the request path. An ApproovException raised by a
     * standard decision during the call, or by message signing, is passed through unchanged. Any other
     * ApproovException and any RuntimeException is logged naming the hook and converted to an
     * ApproovException with the original as its cause, so that the request fails through the normal Volley
     * error handling and the app receives it as a VolleyError.
     *
     * @param hook is the name of the hook, for the log and the exception message
     * @param call is the call into the mutator
     * @return the result of the hook
     * @throws ApproovException if the hook throws one, or throws a RuntimeException
     */
    static <T> T callMutator(String hook, MutatorHook<T> call) throws ApproovException {
        return callMutator(hook, call, false);
    }

    /**
     * Calls a hook of the installed service mutator on the request path as callMutator(hook, call),
     * except that an exception raised by a standard decision may be ignored, in which case null is
     * returned. This is used where the standard decisions never abort a request but an app's own hook
     * may, such as for a token fetch failure for a host that is not in the SDK pin set.
     *
     * @param hook is the name of the hook
     * @param call is the call into the mutator
     * @param ignoreStandard is true if an exception raised by a standard decision is to be ignored
     * @return the result of the hook, or null if an exception raised by a standard decision was ignored
     * @throws ApproovException if the hook throws one, or throws a RuntimeException
     */
    static <T> T callMutator(String hook, MutatorHook<T> call, boolean ignoreStandard) throws ApproovException {
        Set<Throwable> previous = standardDecisions.get();
        Set<Throwable> made = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        standardDecisions.set(made);
        try {
            return call.call();
        } catch (ApproovException e) {
            // a standard decision keeps its form, even if caught and rethrown unchanged
            if (made.contains(e)) {
                if (ignoreStandard)
                    return null;
                throw e;
            }
            throw mutatorFailure(hook, e);
        } catch (RuntimeException e) {
            throw mutatorFailure(hook, e);
        } finally {
            if (previous == null)
                standardDecisions.remove();
            else
                standardDecisions.set(previous);
        }
    }

    /**
     * Converts an exception thrown by a hook of the installed service mutator into an ApproovException
     * with the original as its cause, logged at error level naming the hook.
     *
     * @param hook is the name of the hook
     * @param e is the exception the hook threw
     * @return the exception to throw
     */
    static ApproovException mutatorFailure(String hook, Exception e) {
        String message = "ApproovServiceMutator." + hook + " failed: " + e;
        ApproovLog.e(TAG, message);
        return new ApproovException(message, e);
    }

    /**
     * Determines if a header value can be carried by the network stack unchanged, which allows horizontal
     * tab and printable ASCII only. A secure string may break this rule, while a token or trace ID that does
     * is reported as an SDK problem.
     *
     * @param value is the header value
     * @return true if the value can be set, false otherwise
     */
    static boolean isSafeHeaderValue(String value) {
        if (value == null)
            return true;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c != '\t') && ((c < 0x20) || (c > 0x7e)))
                return false;
        }
        return true;
    }

    /**
     * Reports a header value, set from a value the app supplied, that a header cannot carry. It is logged
     * at error level and returned as an ApproovException naming the header, never quoting the value.
     *
     * @param header is the header name
     * @return the exception to throw
     */
    static ApproovException unsafeHeaderValue(String header) {
        String message = "Approov header " + header + ": invalid character in value";
        ApproovLog.e(TAG, message);
        return new ApproovException(message);
    }

    /**
     * Reports a value issued by the Approov SDK (a token or a trace ID) that a header cannot carry, which
     * is an SDK problem rather than an app configuration error. It is logged at error level and returned
     * as an ApproovException naming the header, never quoting the value.
     *
     * @param what is what the SDK issued, such as "token"
     * @param header is the header name
     * @return the exception to throw
     */
    static ApproovException unsafeSdkValue(String what, String header) {
        String message = "Approov header " + header + ": invalid character in SDK " + what;
        ApproovLog.e(TAG, message);
        return new ApproovException(message);
    }

    /**
     * Gets the name of a token fetch status as the SDK reports it, which is also the value written in place
     * of a secure string placeholder that could not be fetched.
     *
     * @param approovResults is the token fetch result
     * @return the status name
     */
    static String statusName(Approov.TokenFetchResult approovResults) {
        return approovResults.getStatus().name();
    }

    /**
     * Describes a fetch result for a log line or an exception message as the status name and any ARC and
     * rejection reasons, such as "REJECTED, ARC 1A2B, rejection reasons rooted". It never includes a token,
     * a secure string or a placeholder.
     *
     * @param approovResults is the fetch result
     * @return the description of the fetch result
     */
    static String describeStatus(Approov.TokenFetchResult approovResults) {
        StringBuilder sb = new StringBuilder(approovResults.getStatus().name());
        String arc = approovResults.getARC();
        if ((arc != null) && !arc.isEmpty())
            sb.append(", ARC ").append(arc);
        String reasons = approovResults.getRejectionReasons();
        if ((reasons != null) && !reasons.isEmpty())
            sb.append(", rejection reasons ").append(reasons);
        return sb.toString();
    }

    /**
     * Gets the host of a URL for a log line or an exception message, which never carries its path or query
     * as they may hold personal data or a secret.
     *
     * @param url is the URL
     * @return the host, or "a URL without a host" if there is none
     */
    static String loggableHost(String url) {
        try {
            String host = (url != null) ? new URL(url).getHost() : null;
            return ((host != null) && !host.isEmpty()) ? host : "a URL without a host";
        } catch (MalformedURLException e) {
            return "a URL without a host";
        }
    }

    /**
     * Normalizes a host for comparison with the keys of the SDK pin set: lowercase, without one trailing
     * dot and without the brackets of an IPv6 address.
     *
     * @param host is the host
     * @return the normalized host
     */
    static String normalizeHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.endsWith("."))
            normalized = normalized.substring(0, normalized.length() - 1);
        if (normalized.startsWith("[") && normalized.endsWith("]"))
            normalized = normalized.substring(1, normalized.length() - 1);
        return normalized;
    }

    /**
     * Determines if a host is an Approov API domain, that is a key of the SDK public-key-sha256 pin set
     * other than the "*" managed trust roots key, compared without regard to case and ignoring one
     * trailing dot. An empty pin set, or one the SDK fails to provide, lists no host. This only decides
     * what happens to a request whose token fetch failed, as one to a host that is not listed is sent
     * untouched unless the app's own mutator aborts it.
     *
     * @param host is the request host
     * @return true if the host is a key of the pin set, false otherwise
     */
    static boolean isApproovApiHost(String host) {
        if ((host == null) || host.isEmpty())
            return false;
        Map<String, List<String>> pins;
        try {
            pins = Approov.getPins("public-key-sha256");
        } catch (RuntimeException e) {
            // a pin set that cannot be read lists no host
            ApproovLog.e(TAG, "Approov SDK getPins failed: " + e);
            return false;
        }
        if (pins == null)
            return false;
        String wanted = normalizeHost(host);
        for (String domain : pins.keySet()) {
            if ((domain != null) && !domain.equals("*") && normalizeHost(domain).equals(wanted))
                return true;
        }
        return false;
    }

    /**
     * Builds the value of the Approov token header from a token fetch result, accounting for the option to
     * use the fetch status as the value when no token is available.
     *
     * @param prefix is the prefix to be placed before the token
     * @param approovResults is the token fetch result
     * @return the value to set on the Approov token header
     */
    static String buildTokenHeaderValue(String prefix, Approov.TokenFetchResult approovResults) {
        String token = approovResults.getToken();
        if (token == null)
            token = "";
        if (token.isEmpty() && getUseApproovStatusIfNoToken())
            return prefix + statusName(approovResults);
        return prefix + token;
    }

    /**
     * Gets the token header name and prefix together, so that a request never combines the header of one
     * configuration with the prefix of another if the app changes them while requests are in flight.
     *
     * @return a two element array of the header name and prefix
     */
    static synchronized String[] snapshotTokenHeader() {
        return new String[] { approovTokenHeader, (approovTokenPrefix != null) ? approovTokenPrefix : "" };
    }

    /**
     * Initializes the ApproovService with an Approov account ID and comment. A non-empty account ID is always
     * passed to the Approov SDK with the comment unchanged and the SDK decides: a repeat with the same account
     * ID and comment returns at once, while anything else the SDK rejects is thrown unchanged with the service
     * state untouched. An empty account ID enables the service in bypass mode, without Approov protection,
     * and is ignored once protection is enabled. Each initialization that is not ignored resets the
     * configuration to its defaults (headers, exclusions, the service mutator, and so any message signing),
     * so make any configuration calls after initialize.
     *
     * @param context is the Application context
     * @param config is your Approov account ID, or an empty string for bypass mode with no SDK initialization
     * @param comment is the comment passed to the SDK unchanged, or null for no comment
     * @throws IllegalArgumentException if the context or account ID is null, or the SDK rejects the account ID
     * @throws IllegalStateException if the SDK is already initialized with a different account ID or comment
     */
    public static synchronized void initialize(Context context, String config, String comment) {
        if (context == null)
            throw new IllegalArgumentException("initialize: null context");
        if (config == null)
            throw new IllegalArgumentException("config must not be null; pass \"\" for bypass mode");

        if (config.isEmpty()) {
            if (approovProtectionEnabled) {
                // an empty account ID never downgrades active Approov protection and is not passed to the SDK
                ApproovLog.i(TAG, "initialize: empty config ignored, Approov protection already enabled");
            } else {
                ApproovLog.i(TAG, "initialize: bypass mode, Approov protection not active");
                resetConfiguration();
                isInitialized = true;
            }
            return;
        }

        // pass every non-empty account ID to the SDK with the comment exactly as given, as the SDK is the
        // only judge of a repeat call and any exception it throws reaches the caller with the state untouched
        boolean newlyInitialized;
        try {
            newlyInitialized = Approov.initialize(context.getApplicationContext(), config, "auto", comment);
        } catch (RuntimeException e) {
            ApproovLog.e(TAG, "initialize: Approov SDK failed: " + e);
            throw e;
        }
        boolean protectionWasEnabled = approovProtectionEnabled;
        resetConfiguration();
        isInitialized = true;
        approovProtectionEnabled = true;
        if (newlyInitialized)
            ApproovLog.i(TAG, "initialize: Approov protection enabled");
        else
            ApproovLog.d(TAG, "initialize: Approov SDK already initialized with the same config and comment");
        if (!protectionWasEnabled) {
            try {
                Approov.setUserProperty("approov-service-volley/" + BuildConfig.APPROOV_SERVICE_VERSION);
            } catch (RuntimeException e) {
                // the property is diagnostic only and must not fail a successful initialization
                ApproovLog.e(TAG, "initialize: Approov user property not set: " + e);
            }
        }
    }

    /**
     * Resets the configuration to its defaults, as each initialization does. The logging level is kept.
     */
    private static synchronized void resetConfiguration() {
        lastARC = "";
        hurlStack = new ApproovHurlStack();
        approovTokenHeader = APPROOV_TOKEN_HEADER;
        approovTokenPrefix = APPROOV_TOKEN_PREFIX;
        approovTraceIDHeader = APPROOV_TRACE_ID_HEADER;
        bindingHeader = null;
        useApproovStatusIfNoToken = false;
        exclusionURLRegexs = new HashMap<>();
        serviceMutator = ApproovServiceMutator.DEFAULT;
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
     * Sets a flag indicating if the Approov fetch status (for example "NO_NETWORK"
     * or "MITM_DETECTED") should be used as the token header value when the
     * request is still allowed to proceed but no real token is available.
     *
     * @param shouldUse true if the fetch status should be used as the token value
     */
    public static synchronized void setUseApproovStatusIfNoToken(boolean shouldUse) {
        ApproovLog.d(TAG, "setUseApproovStatusIfNoToken " + shouldUse);
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
     * Determines if the ApproovService is enabled, which is true once any initialize has succeeded,
     * including bypass mode with an empty account ID. Before that, requests made through the stack are
     * sent without Approov processing.
     *
     * @return true if the service has been enabled by a successful initialize, false otherwise
     */
    public static synchronized boolean isApproovServiceEnabled() {
        return isInitialized;
    }

    /**
     * Determines if Approov protection is enabled, which is true once the Approov SDK has been initialized
     * by a successful initialize with a non-empty account ID. It is false before initialization and in
     * bypass mode, where requests are sent without Approov processing.
     *
     * @return true if the Approov SDK is initialized and requests are protected, false otherwise
     */
    public static synchronized boolean isApproovProtectionEnabled() {
        return isInitialized && approovProtectionEnabled;
    }

    /**
     * Indicates whether the service layer has been initialized, bypass mode included. This is the same as
     * isApproovServiceEnabled().
     *
     * @return true if the service layer has been initialized, false otherwise
     */
    public static synchronized boolean isInitialized() {
        return isApproovServiceEnabled();
    }

    /**
     * Indicates whether Approov protection is enabled for this service layer instance. If initialization
     * used an empty account ID then the layer is initialized but Approov protection is bypassed. This is
     * the same as isApproovProtectionEnabled().
     *
     * @return true if Approov protection is enabled, false otherwise
     */
    public static synchronized boolean isApproovEnabled() {
        return isApproovProtectionEnabled();
    }

    /**
     * Resets the ApproovService state. This should only be used for testing.
     */
    @VisibleForTesting
    static synchronized void reset() {
        hurlStack = null;
        isInitialized = false;
        approovProtectionEnabled = false;
        lastARC = "";
        messageSignatureDeprecationLogged.set(false);
        useApproovStatusIfNoToken = false;
        approovTokenHeader = null;
        approovTokenPrefix = null;
        approovTraceIDHeader = null;
        bindingHeader = null;
        exclusionURLRegexs = null;
        serviceMutator = ApproovServiceMutator.DEFAULT;
        ApproovLog.setLevel(ApproovLogLevel.INFO);
    }

    /**
     * Sets the logging level of the service layer. ERROR writes errors only, WARNING adds warnings, INFO
     * (the default) adds information and DEBUG adds the debug lines, including the loggable token of each
     * request whose claims include the device ID. OFF writes nothing. The level may be set at any time and
     * is not reset by initialize. Debug logging enabled for the ApproovService tag, with
     * "adb shell setprop log.tag.ApproovService DEBUG", raises any level but OFF to DEBUG without a rebuild.
     * Note that the logging of the Approov SDK itself is not affected.
     *
     * @param level is the logging level to be used
     * @throws IllegalArgumentException if the level is null
     */
    public static void setLoggingLevel(ApproovLogLevel level) {
        if (level == null)
            throw new IllegalArgumentException("setLoggingLevel: null level");
        ApproovLog.setLevel(level);
        ApproovLog.d(TAG, "setLoggingLevel " + level);
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
            ApproovLog.d(TAG, "setDevKey");
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
        catch (IllegalArgumentException e) {
            throw new ApproovException("IllegalArgument: " + e.getMessage());
        }
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional prefix String (such as
     * "Bearer "). By default the token is provided on "Approov-Token" with no prefix.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header, or null for none
     */
    public static synchronized void setTokenHeader(String header, String prefix) {
        ApproovLog.d(TAG, "setTokenHeader " + header + ", " + prefix);
        approovTokenHeader = header;
        // A null prefix is equivalent to no prefix (empty string). Storing null here would later
        // concatenate the literal string "null" in front of the token, producing a malformed
        // header value. Normalise to "".
        approovTokenPrefix = (prefix == null) ? "" : prefix;
    }

    /**
     * Gets the header that is used to add the Approov token.
     *
     * @return String of the header used for the Approov token
     */
    public static synchronized String getTokenHeader() {
        return approovTokenHeader;
    }

    /**
     * Gets the prefix that is added before the Approov token in the header.
     *
     * @return String of the prefix added before the Approov token
     */
    public static synchronized String getTokenPrefix() {
        return approovTokenPrefix;
    }

    /**
     * Sets the header name that is used to pass any optional Approov TraceID debug value. Passing null
     * disables the header.
     *
     * @param header is the name of the header on which to place the Approov TraceID, or null to disable it
     */
    public static synchronized void setTraceIDHeader(String header) {
        ApproovLog.d(TAG, "setTraceIDHeader " + header);
        approovTraceIDHeader = header;
    }

    /**
     * Gets the header used to hold the optional Approov TraceID.
     *
     * @return the header name used for the Approov TraceID, or null if disabled
     */
    public static synchronized String getTraceIDHeader() {
        return approovTraceIDHeader;
    }

    /**
     * Sets the header that the Approov token is added on, as well as an optional prefix String.
     * Deprecated: use setTokenHeader instead.
     *
     * @param header is the header to place the Approov token on
     * @param prefix is any prefix String for the Approov token header, or null for none
     * @deprecated Use setTokenHeader.
     */
    @Deprecated
    public static void setApproovHeader(String header, String prefix) {
        setTokenHeader(header, prefix);
    }

    /**
     * Sets the header that any optional Approov TraceID debug value is added on.
     * Deprecated: use setTraceIDHeader instead.
     *
     * @param header is the header to place the Approov TraceID on, or null to disable the header
     * @deprecated Use setTraceIDHeader.
     */
    @Deprecated
    public static void setApproovTraceIDHeader(String header) {
        setTraceIDHeader(header);
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
        ApproovLog.d(TAG, "setBindingHeader " + header);
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
        ApproovLog.d(TAG, "Applied ApproovServiceMutator: " + mutator.toString());
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
                ApproovLog.d(TAG, "addExclusionURLRegex " + urlRegex);
            } catch (PatternSyntaxException e) {
                ApproovLog.e(TAG, "addExclusionURLRegex " + urlRegex + " error: " + e.getMessage());
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
            ApproovLog.d(TAG, "removeExclusionURLRegex " + urlRegex);
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
            ApproovLog.e(TAG, "precheck: SDK not initialized");
            throw new ApproovException("precheck: SDK not initialized");
        }
        // try and fetch a non-existent secure string in order to check for a rejection
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait("precheck-dummy-key", null));
            ApproovLog.d(TAG, "precheck: " + approovResults.getStatus().toString());
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
            ApproovLog.e(TAG, "getDeviceID: SDK not initialized");
            throw new ApproovException("getDeviceID: SDK not initialized");
        }
        try {
            String deviceID = Approov.getDeviceID();
            ApproovLog.d(TAG, "getDeviceID: " + deviceID);
            return deviceID;
        }
        catch (IllegalStateException e) {
            throw new ApproovException("IllegalState: " + e.getMessage());
        }
    }

    /**
     * Checks that Approov protection is enabled before a public method uses the Approov SDK, so that the
     * SDK is not called before initialization or in bypass mode.
     *
     * @param method is the name of the public method, for the exception message
     * @throws ApproovException if Approov protection is not enabled
     */
    private static void requireProtection(String method) throws ApproovException {
        if (!isApproovProtectionEnabled()) {
            ApproovLog.e(TAG, method + ": SDK not initialized");
            throw new ApproovException(method + ": SDK not initialized");
        }
    }

    /**
     * Gets the current time in milliseconds since the epoch, adjusted to the Approov servers' clock. This
     * is the device clock corrected by the offset the Approov SDK learns at each attestation, and before the
     * first attestation it is the device clock. Message signatures take their created and expires times from
     * it, so that a device whose clock is wrong still signs within the window your backend accepts. Use it for
     * timestamps of your own that your backend compares with its clock. If the server time is not available,
     * it is the device clock.
     *
     * @return the current time in milliseconds since the epoch, adjusted to the Approov servers' clock
     * @throws ApproovException if Approov protection is not enabled or the SDK call fails
     */
    public static long getServerAdjustedCurrentTimeMS() throws ApproovException {
        requireProtection("getServerAdjustedCurrentTimeMS");
        try {
            return sdkServerAdjustedTimeMS();
        } catch (RuntimeException e) {
            ApproovException wrapped = new ApproovException(e);
            ApproovLog.e(TAG, "getServerAdjustedCurrentTimeMS: " + wrapped.getMessage());
            throw wrapped;
        }
    }

    /**
     * Gets the time message signatures are stamped with, in milliseconds since the epoch: the server adjusted
     * time while protection is enabled, so that a wrong device clock does not put created and expires outside
     * the backend's window, and the device clock otherwise. A signature is never left out for want of it, so
     * an SDK failure falls back to the device clock and is logged.
     *
     * @return the time for the created and expires signature parameters, in milliseconds since the epoch
     */
    static long signatureTimeMillis() {
        if (isApproovProtectionEnabled()) {
            try {
                return sdkServerAdjustedTimeMS();
            } catch (RuntimeException e) {
                ApproovLog.w(TAG, "Message signing: server adjusted time unavailable, using the device clock: " + e);
            }
        }
        return System.currentTimeMillis();
    }

    /**
     * Gets the server adjusted time from the Approov SDK.
     *
     * @return the current time in milliseconds since the epoch, adjusted to the Approov servers' clock
     * @throws RuntimeException as the SDK call throws it, such as an IllegalStateException before
     *         initialization, or an IllegalStateException if the Approov SDK the app runs with is older than
     *         the one the package is built against and does not have the method
     */
    private static long sdkServerAdjustedTimeMS() {
        try {
            return Approov.getServerAdjustedCurrentTimeMS();
        } catch (LinkageError e) {
            throw new IllegalStateException("Approov SDK has no getServerAdjustedCurrentTimeMS", e);
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
            ApproovLog.e(TAG, "setDataHashInToken: SDK not initialized");
            throw new ApproovException("setDataHashInToken: SDK not initialized");
        }
        try {
            Approov.setDataHashInToken(data);
            ApproovLog.d(TAG, "setDataHashInToken");
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
            ApproovLog.e(TAG, "fetchToken: SDK not initialized");
            throw new ApproovException("fetchToken: SDK not initialized");
        }
        // fetch the Approov token
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchApproovTokenAndWait(url));
            ApproovLog.d(TAG, "fetchToken: " + approovResults.getStatus().toString());
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
     * @deprecated Use getAccountMessageSignature. The first call logs a deprecation warning.
     */
    @Deprecated
    public static String getMessageSignature(String message) throws ApproovException {
        if (messageSignatureDeprecationLogged.compareAndSet(false, true))
            ApproovLog.w(TAG, "getMessageSignature is deprecated: use getAccountMessageSignature");
        return getAccountMessageSignature(message);
    }

    // true once the deprecation warning of getMessageSignature has been logged
    private static final AtomicBoolean messageSignatureDeprecationLogged = new AtomicBoolean();

    /**
     * Gets the account message signature for the given message.
     *
     * @param message is the message whose content is to be signed
     * @return String of the base64 encoded account message signature
     * @throws ApproovException if there was a problem
     */
    public static String getAccountMessageSignature(String message) throws ApproovException {
        if (!isApproovEnabled()) {
            ApproovLog.e(TAG, "getAccountMessageSignature: SDK not initialized");
            throw new ApproovException("getAccountMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getAccountMessageSignature(message);
            ApproovLog.d(TAG, "getAccountMessageSignature");
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
            ApproovLog.e(TAG, "getInstallMessageSignature: SDK not initialized");
            throw new ApproovException("getInstallMessageSignature: SDK not initialized");
        }
        try {
            String signature = Approov.getInstallMessageSignature(message);
            ApproovLog.d(TAG, "getInstallMessageSignature");
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
            ApproovLog.e(TAG, "fetchSecureString: SDK not initialized");
            throw new ApproovException("fetchSecureString: SDK not initialized");
        }
        // determine the type of operation as the values themselves cannot be logged
        String type = "lookup";
        if (newDef != null)
            type = "definition";

        // fetch any secure string keyed by the value, catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(key, newDef));
            ApproovLog.d(TAG, "fetchSecureString " + type + ": " + key + ", " + approovResults.getStatus().toString());
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
            ApproovLog.e(TAG, "fetchCustomJWT: SDK not initialized");
            throw new ApproovException("fetchCustomJWT: SDK not initialized");
        }
        // fetch the custom JWT catching any exceptions the SDK might throw
        Approov.TokenFetchResult approovResults;
        try {
            approovResults = fetchRecording(() -> Approov.fetchCustomJWTAndWait(payload));
            ApproovLog.d(TAG, "fetchCustomJWT: " + approovResults.getStatus().toString());
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
     * Gets the Attestation Response Code (ARC) from the most recent token, secure string or custom JWT
     * fetch made by this layer, either for a request or by a direct method. It performs no fetch of its
     * own, so it can be read after a rejected request to correlate with your backend API. An empty string
     * is returned if no fetch has been made, if the last fetch carried no ARC or failed without a result,
     * or if ARC is not enabled for the account. Note that it is preferable to obtain the ARC on the server
     * side where possible.
     *
     * @return the ARC of the most recent fetch, or an empty string
     */
    public static synchronized String getLastARC() {
        return lastARC;
    }

    /**
     * Records the ARC of a fetch result as the most recent one. An empty or null ARC clears the previous
     * value, as the ARC belongs to the last fetch.
     *
     * @param approovResults is the fetch result, or null if the fetch failed without a result
     * @return the fetch result passed in
     */
    static synchronized Approov.TokenFetchResult recordLastARC(Approov.TokenFetchResult approovResults) {
        String arc = (approovResults != null) ? approovResults.getARC() : null;
        lastARC = (arc != null) ? arc : "";
        return approovResults;
    }

    // a fetch made by the SDK
    interface SdkFetch {
        Approov.TokenFetchResult fetch();
    }

    /**
     * Performs a fetch with the SDK and records its ARC. A fetch that throws or returns no result leaves no
     * ARC.
     *
     * @param fetch is the SDK call
     * @return the fetch result
     */
    static Approov.TokenFetchResult fetchRecording(SdkFetch fetch) {
        recordLastARC(null);
        return recordLastARC(fetch.fetch());
    }

    /**
     * Sets an install attributes token to be sent to the server and associated with this particular
     * app installation for future Approov token fetches, as setInstallAttrsInToken does. This is the name
     * shared by all Approov packages.
     *
     * @param attrs is the signed JWT holding the new install attributes
     * @throws ApproovException if the attrs parameter is invalid or the SDK is not initialized
     */
    public static void setInstallAttributes(String attrs) throws ApproovException {
        setInstallAttrsInToken(attrs);
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
            ApproovLog.e(TAG, "setInstallAttrsInToken: SDK not initialized");
            throw new ApproovException("setInstallAttrsInToken: SDK not initialized");
        }
        try {
            Approov.setInstallAttrsInToken(attrs);
            ApproovLog.d(TAG, "setInstallAttrsInToken");
        } catch (IllegalArgumentException e) {
            ApproovLog.e(TAG, "setInstallAttrsInToken failed with IllegalArgument: " + e.getMessage());
            throw new ApproovException("Illegal Argument: " + e.getMessage());
        } catch (IllegalStateException e) {
            ApproovLog.e(TAG, "setInstallAttrsInToken failed with IllegalState: " + e.getMessage());
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
            urlStatus = fetchRecording(() -> Approov.fetchApproovTokenAndWait(url));
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
            final String secureStringKey = value.substring(prefix.length());
            try {
                approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(secureStringKey, null));
                ApproovLog.d(TAG, "Substituting header: " + substitutionHeader + ", " + approovResults.getStatus().toString());
            }
            catch (IllegalStateException e) {
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }

            if (getServiceMutator().handleRequestHeaderSubstitutionResult(approovResults, substitutionHeader)) {
                // Only overwrite the header when a non-empty secure string is available.
                // A null or empty result means substitution yielded no value; the original
                // placeholder is preserved in place (TESTING_REQUIREMENTS §2 Missing Artifacts Fallback).
                String secureString = approovResults.getSecureString();
                if (secureString != null && !secureString.isEmpty()) {
                    headers.put(substitutionHeader, prefix + secureString);
                }
            }
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
            urlStatus = fetchRecording(() -> Approov.fetchApproovTokenAndWait(url));
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
                approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(value, null));
                ApproovLog.d(TAG, "Substituting query param: " + queryParam + ", " + approovResults.getStatus().toString());
            }
            catch (IllegalStateException e) {
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }

            if (getServiceMutator().handleRequestQueryParamSubstitutionResult(approovResults, queryParam)) {
                // Only overwrite the parameter when a non-empty secure string is available.
                // A null or empty result means substitution yielded no value; the original
                // placeholder is preserved in place (TESTING_REQUIREMENTS §2 Missing Artifacts Fallback).
                String secureString = approovResults.getSecureString();
                if (secureString != null && !secureString.isEmpty()) {
                    params.put(queryParam, secureString);
                }
            }
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
            urlStatus = fetchRecording(() -> Approov.fetchApproovTokenAndWait(url));
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
        Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            // we have found an occurrence of the query parameter to be replaced so we look up the existing
            // value as a key for a secure string
            String queryValue = matcher.group(1);
            Approov.TokenFetchResult approovResults;
            try {
                approovResults = fetchRecording(() -> Approov.fetchSecureStringAndWait(queryValue, null));
            }
            catch (IllegalStateException e) {
                throw new ApproovException(e);
            }
            catch (IllegalArgumentException e) {
                throw new ApproovException(e);
            }
            ApproovLog.d(TAG, "Substituting query parameter: " + queryParameter + ", " + approovResults.getStatus().toString());
            if (getServiceMutator().handleRequestQueryParamSubstitutionResult(approovResults, queryParameter)) {
                // Only substitute when a non-empty secure string is available.
                // A null or empty result means substitution yielded no value; the original
                // placeholder is preserved in place (TESTING_REQUIREMENTS §2 Missing Artifacts Fallback).
                String secureString = approovResults.getSecureString();
                if (secureString != null && !secureString.isEmpty()) {
                    return new StringBuilder(url).replace(matcher.start(1),
                            matcher.end(1), secureString).toString();
                }
            }
        }
        return url;
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
                    String hash = sha256Base64(x509Cert.getPublicKey().getEncoded());
                    if (hostPins.contains(hash))
                        return true;
                }
                else
                    ApproovLog.e(TAG, "Certificate not X.509");
            }

            // the connection is rejected
            ApproovLog.w(TAG, "Pinning rejection for " + hostname);
            return false;
        } catch (SSLException e) {
            ApproovLog.e(TAG, "Delegate Exception");
            throw new RuntimeException(e);
        }
        return false;
    }

    /**
     * Computes the base64-encoded SHA-256 of the given bytes, matching the Approov
     * "public-key-sha256" pin form. Uses the platform MessageDigest/Base64 so the service layer
     * carries no third-party dependency purely for pin hashing.
     *
     * @param data the bytes to hash (a certificate's encoded public key)
     * @return the base64 (no-wrap) SHA-256 digest
     */
    private static String sha256Base64(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every Android platform; a failure here is fatal.
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
