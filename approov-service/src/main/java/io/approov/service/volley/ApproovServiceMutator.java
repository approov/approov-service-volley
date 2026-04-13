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
 * ApproovServiceMutator provides an interface for modifying the behavior of
 * the ApproovService class by overriding the default implementations of the
 * defined callbacks.
 */
public interface ApproovServiceMutator {
    /**
     * Default mutator that provides standard behavior with no changes.
     */
    ApproovServiceMutator DEFAULT = new ApproovServiceMutator() {
        @Override
        public String toString() {
            return "ApproovServiceMutator.DEFAULT";
        }
    };

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
            throw new ApproovException("handleRequestShouldProcess method was passed a request that is null!");
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
     * Decides how to handle the token fetch result for an Approov-protected Volley request.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param url the URL for which the token was requested
     * @return true if request processing should continue through the mutator pipeline,
     *         false if the request should proceed without any additional Approov changes
     * @throws ApproovException if the request should fail
     */
    @SuppressWarnings("deprecation")
    default boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        switch (status) {
            case SUCCESS:
                return true;
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                if (ApproovService.getUseApproovStatusIfNoToken()) {
                    return true;
                }
                throw new ApproovNetworkException(status,
                        "Approov token fetch for " + url + ": " + status.toString());
            case NO_APPROOV_SERVICE:
            case UNKNOWN_URL:
            case UNPROTECTED_URL:
                return false;
            default:
                throw new ApproovFetchStatusException(status,
                        "Approov token fetch for " + url + ": " + status.toString());
        }
    }

    /**
     * Determines the value to use for the Approov token header after a fetch result is accepted
     * for continued request processing.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param url the URL for which the token was requested
     * @return the value to set on the Approov token header, or null to leave the header unset
     * @throws ApproovException if the request should fail
     */
    default String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        if (approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS) {
            if ((approovResults.getToken() == null || approovResults.getToken().isEmpty())
                    && ApproovService.getUseApproovStatusIfNoToken()) {
                return ApproovService.getApproovTokenHeaderValueOrStatus(approovResults);
            }
            return ApproovService.getApproovTokenHeaderValue(approovResults);
        }
        if (!ApproovService.getUseApproovStatusIfNoToken()) {
            return null;
        }
        switch (approovResults.getStatus()) {
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                return ApproovService.getApproovTokenHeaderValueOrStatus(approovResults);
            default:
                return null;
        }
    }

    /**
     * Decides how to handle a secure string fetch result while substituting a header.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param header the header being substituted
     * @return true if the substitution should proceed, false if it should be skipped
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header)
            throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        String arc = approovResults.getARC();
        String rejectionReasons = approovResults.getRejectionReasons();
        switch (status) {
            case SUCCESS:
                return true;
            case REJECTED:
                throw new ApproovRejectionException(
                        "Header substitution for " + header + ": " + status.toString() + ": "
                                + arc + " " + rejectionReasons,
                        arc, rejectionReasons);
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status,
                        "Header substitution for " + header + ": " + status.toString());
            case UNKNOWN_KEY:
                return false;
            default:
                throw new ApproovFetchStatusException(status,
                        "Header substitution for " + header + ": " + status.toString());
        }
    }

    /**
     * Decides how to handle a secure string fetch result while substituting a query parameter.
     *
     * @param approovResults the TokenFetchResult from Approov
     * @param queryKey the query parameter key being substituted
     * @return true if the substitution should proceed, false if it should be skipped
     * @throws ApproovException if the result should be surfaced as an error
     */
    @SuppressWarnings("deprecation")
    default boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult approovResults, String queryKey)
            throws ApproovException {
        Approov.TokenFetchStatus status = approovResults.getStatus();
        String arc = approovResults.getARC();
        String rejectionReasons = approovResults.getRejectionReasons();
        switch (status) {
            case SUCCESS:
                return true;
            case REJECTED:
                throw new ApproovRejectionException(
                        "Query parameter substitution for " + queryKey + ": " + status.toString() + ": "
                                + arc + " " + rejectionReasons,
                        arc, rejectionReasons);
            case NO_NETWORK:
            case POOR_NETWORK:
            case MITM_DETECTED:
                throw new ApproovNetworkException(status,
                        "Query parameter substitution for " + queryKey + ": " + status.toString());
            case UNKNOWN_KEY:
                return false;
            default:
                throw new ApproovFetchStatusException(status,
                        "Query parameter substitution for " + queryKey + ": " + status.toString());
        }
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
