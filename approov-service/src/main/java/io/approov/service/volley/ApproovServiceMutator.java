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

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ApproovServiceMutator provides an interface for modifying the behavior of the ApproovService class by
 * overriding the default implementations of the defined callbacks. Opportunities to modify behavior are
 * offered at key points in the service and attestation flows. All the methods have default
 * implementations, so an implementing class need only override the methods it is interested in.
 * <p>
 * Two standard mutators are provided. CLOSE_FAILURE, whose decisions are also the interface defaults,
 * aborts a request on a token fetch failure other than NO_APPROOV_SERVICE. ALWAYS_PROCEED never aborts a
 * request, sending it with an empty token header (or the token fetch status, see
 * ApproovService.setUseApproovStatusIfNoToken) and leaving the backend to decide.
 * DEFAULT is the mutator in force until the app installs its own, which is CLOSE_FAILURE. Under both
 * standard mutators a secure string that cannot be obtained never aborts a request. Message signing is
 * itself a mutator, ApproovDefaultMessageSigning.
 */
public interface ApproovServiceMutator {
    /**
     * Decisions that abort a request on a token fetch failure, which are also the interface defaults. A
     * request proceeds on SUCCESS and NO_APPROOV_SERVICE, UNKNOWN_URL and UNPROTECTED_URL get no Approov
     * header, and every other token fetch status throws an ApproovException subclass. A secure string is
     * substituted on SUCCESS, while any other secure string status skips the substitution and the request
     * proceeds.
     */
    public static final ApproovServiceMutator CLOSE_FAILURE = new ApproovServiceMutator() {
        @Override
        public String toString() {
            return "ApproovServiceMutator.CLOSE_FAILURE";
        }
    };

    /**
     * Decisions that never abort a request. Every token fetch status except UNKNOWN_URL and UNPROTECTED_URL
     * proceeds with the token header (holding the token on SUCCESS, otherwise an empty token or the status)
     * and any trace header, and a secure string is only substituted on SUCCESS.
     */
    public static final ApproovServiceMutator ALWAYS_PROCEED = new ApproovServiceMutator() {
        @Override
        public String toString() {
            return "ApproovServiceMutator.ALWAYS_PROCEED";
        }

        @Override
        public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
            switch (approovResults.getStatus()) {
                case UNKNOWN_URL:
                case UNPROTECTED_URL:
                    // continue without any headers for unprotected URLs (anti-MitM)
                    return false;
                default:
                    // SUCCESS adds the token, while any failure proceeds with an empty token header or the
                    // status in it
                    return true;
            }
        }
    };

    /**
     * The decisions in force until the app installs its own mutator, which are reinstated by
     * ApproovService.setServiceMutator(null). This is CLOSE_FAILURE, and an app that wants a fixed
     * behaviour should name CLOSE_FAILURE or ALWAYS_PROCEED explicitly.
     */
    public static final ApproovServiceMutator DEFAULT = CLOSE_FAILURE;

    /**
     * Determines if a token fetch status is a network failure, meaning that the attestation could not be
     * performed because of the network rather than because of the app or device. These are NO_NETWORK,
     * POOR_NETWORK and MITM_DETECTED, which reports a fundamental TLS trust failure to the Approov cloud or
     * a captive portal.
     *
     * @param status is the token fetch status to classify
     * @return true if the status is a network failure, false otherwise
     */
    static boolean isNetworkFailure(Approov.TokenFetchStatus status) {
        switch (status) {
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                return true;
            default:
                return false;
        }
    }

    /**
     * Decides how to handle the token fetch result from an ApproovService.precheck() operation.
     *
     * @param approovResults the TokenFetchResult obtained by ApproovService.precheck()
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        String arc = approovResults.getARC();
        String rejectionReasons = approovResults.getRejectionReasons();
        switch (status) {
            case REJECTED:
                throw new ApproovRejectionException(
                        "precheck: " + status.toString() + ": " + arc + " " + rejectionReasons,
                        arc, rejectionReasons);
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status, "precheck: " + status.toString());
            case SUCCESS:
            case UNKNOWN_KEY:
                break;
            default:
                throw new ApproovFetchStatusException(status, "precheck: " + status.toString());
        }
    }

    /**
     * Decides how to handle the token fetch result from an ApproovService.fetchToken() operation.
     *
     * @param approovResults the TokenFetchResult obtained by ApproovService.fetchToken()
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        switch (status) {
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status, "fetchToken: " + status.toString());
            case SUCCESS:
                break;
            default:
                throw new ApproovFetchStatusException(status, "fetchToken: " + status.toString());
        }
    }

    /**
     * Decides how to handle the token fetch result from an ApproovService.fetchSecureString() operation.
     *
     * @param approovResults the TokenFetchResult obtained by ApproovService.fetchSecureString()
     * @param operation the operation type ("lookup" or "definition")
     * @param key the secure string key
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key)
            throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        String arc = approovResults.getARC();
        String rejectionReasons = approovResults.getRejectionReasons();
        switch (status) {
            case REJECTED:
                throw new ApproovRejectionException(
                        "fetchSecureString " + operation + " for " + key + ": " + status.toString() + ": "
                                + arc + " " + rejectionReasons,
                        arc, rejectionReasons);
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status,
                        "fetchSecureString " + operation + " for " + key + ": " + status.toString());
            case SUCCESS:
            case UNKNOWN_KEY:
                break;
            default:
                throw new ApproovFetchStatusException(status,
                        "fetchSecureString " + operation + " for " + key + ": " + status.toString());
        }
    }

    /**
     * Decides how to handle the token fetch result from an ApproovService.fetchCustomJWT() operation.
     *
     * @param approovResults the TokenFetchResult obtained by ApproovService.fetchCustomJWT()
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        String arc = approovResults.getARC();
        String rejectionReasons = approovResults.getRejectionReasons();
        switch (status) {
            case REJECTED:
                throw new ApproovRejectionException(
                        "fetchCustomJWT: " + status.toString() + ": " + arc + " " + rejectionReasons,
                        arc, rejectionReasons);
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status, "fetchCustomJWT: " + status.toString());
            case SUCCESS:
                break;
            default:
                throw new ApproovFetchStatusException(status, "fetchCustomJWT: " + status.toString());
        }
    }

    /**
     * Decides whether a Volley request should be processed by the Approov network stack.
     *
     * @param request the Volley request about to be processed
     * @param additionalHeaders any existing additional headers passed to the stack
     * @return true if the request should be processed by Approov, false if it should proceed unchanged
     * @throws ApproovException if the request should be aborted
     */
    default boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders)
            throws ApproovException {
        if (request == null) {
            throw ApproovService.standardDecision(new ApproovException(
                    "handleRequestShouldProcess method was passed a request that is null!"));
        }
        String url = request.getUrl();
        for (Pattern pattern : ApproovService.getExclusionURLRegexs().values()) {
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decides how to handle the token fetch result for an Approov-protected Volley request. The default
     * proceeds on SUCCESS, adding the token header, and on NO_APPROOV_SERVICE, with an empty token header
     * (or the status, see setUseApproovStatusIfNoToken). UNKNOWN_URL and UNPROTECTED_URL proceed with no
     * Approov headers. The network failures (see isNetworkFailure) throw ApproovNetworkException, unless the
     * status is used in the token header, in which case they proceed with it, and every other status throws
     * ApproovFetchStatusException.
     * <p>
     * The result decides the Approov headers and the message signing, never the secure strings. True on
     * SUCCESS adds the token and trace headers and any message signature, true on a failure status adds the
     * token header with an empty token or the status and any trace header, and true on UNKNOWN_URL or
     * UNPROTECTED_URL adds nothing. Note that for a failure on a host that is not in the SDK pin set the
     * request is sent untouched whatever this returns, unless the implementation throws its own exception.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param url the URL for which the token was requested
     * @return true if the request should proceed with the Approov headers its status allows, false if it
     *         should proceed without any Approov headers
     * @throws ApproovException if the request should fail
     */
    @SuppressWarnings("deprecation")
    default boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        switch (status) {
            case SUCCESS:
            case NO_APPROOV_SERVICE:
                // NO_APPROOV_SERVICE proceeds with an empty token header (or the status) and any trace ID, as
                // evidence that Approov processing occurred
                return true;
            case UNKNOWN_URL:
            case UNPROTECTED_URL:
                // no Approov headers, as an UNKNOWN_URL host is not added to Approov and an UNPROTECTED_URL
                // host is a secrets-only API that needs no token
                return false;
            default:
                String message = "Approov token fetch for " + ApproovLog.loggableURL(url) + ": " + status;
                if (isNetworkFailure(status)) {
                    // a network failure proceeds if the status is to be sent in the token header instead
                    if (ApproovService.getUseApproovStatusIfNoToken())
                        return true;
                    throw ApproovService.standardDecision(new ApproovNetworkException(status, message));
                }
                throw ApproovService.standardDecision(new ApproovFetchStatusException(status, message));
        }
    }

    /**
     * Gives the value of the Approov token header for a fetch result. This is no longer called: the token
     * header is set from the fetch result whenever handleRequestFetchTokenResult lets a request proceed
     * with the Approov headers, holding the token on SUCCESS and otherwise an empty token, or the status with
     * ApproovService.setUseApproovStatusIfNoToken(true), after the prefix. A mutator that must change the
     * header does so in handleRequestProcessedHeaders.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param url the URL for which the token was requested
     * @return the value the layer sets on the Approov token header for this result
     * @throws ApproovException never by the default implementation
     * @deprecated the token header is set by the layer from the fetch result; this is no longer called
     */
    @Deprecated
    default String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        switch (approovResults.getStatus()) {
            case UNKNOWN_URL:
            case UNPROTECTED_URL:
                // no Approov headers for these
                return null;
            default:
                return ApproovService.buildTokenHeaderValue(ApproovService.snapshotTokenHeader()[1], approovResults);
        }
    }

    /**
     * Decides how to handle a secure string fetch result while substituting a header. The default
     * substitutes the header on SUCCESS and skips it on any other status, with the request proceeding.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param header the header being substituted
     * @return true if the substitution should proceed, false if it should be skipped
     * @throws ApproovException if an overriding implementation aborts the request, which the default never
     *         does
     */
    default boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header)
            throws ApproovException {
        return closeFailureSubstitution(approovResults);
    }

    /**
     * Decides how to handle a secure string fetch result while substituting a query parameter. The default
     * substitutes the query parameter on SUCCESS and skips it on any other status, with the request
     * proceeding.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param queryKey the query parameter key being substituted
     * @return true if the substitution should proceed, false if it should be skipped
     * @throws ApproovException if an overriding implementation aborts the request, which the default never
     *         does
     */
    default boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult approovResults, String queryKey)
            throws ApproovException {
        return closeFailureSubstitution(approovResults);
    }

    /**
     * Decides a secure string substitution for both standard mutators, substituting on SUCCESS and skipping
     * it for any other status. It never throws, as a standard mutator never aborts a request because of a
     * secure string.
     *
     * @param approovResults the secure string fetch result
     * @return true to substitute, false to skip the substitution
     */
    static boolean closeFailureSubstitution(Approov.TokenFetchResult approovResults) {
        return approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS;
    }

    /**
     * Called after the Approov processing has prepared the request headers, allowing further changes.
     *
     * @param request the request being processed
     * @param headers the headers accumulated so far for the request
     * @param changes the mutations already applied during Approov processing
     * @return the final headers to pass to the Volley stack
     * @throws ApproovException if the request should fail
     */
    default Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
            ApproovRequestMutations changes) throws ApproovException {
        if (headers == null) {
            return new LinkedHashMap<>();
        }
        return headers;
    }
}
