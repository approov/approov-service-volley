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

import java.util.List;

/**
 * Stores information about request changes made during Approov processing.
 */
public class ApproovRequestMutations {
    private String tokenHeaderKey;
    private String tokenHeaderPrefix;
    private String traceIDHeaderKey;
    private List<String> substitutionHeaderKeys;
    private String originalURL;
    private List<String> substitutionQueryParamKeys;
    private List<String> addedHeaderKeys;

    /**
     * Gets the header key used for the Approov token.
     *
     * @return the Approov token header key
     */
    public String getTokenHeaderKey() {
        return tokenHeaderKey;
    }

    /**
     * Sets the header key used for the Approov token.
     *
     * @param tokenHeaderKey the Approov token header key
     */
    public void setTokenHeaderKey(String tokenHeaderKey) {
        this.tokenHeaderKey = tokenHeaderKey;
    }

    /**
     * Gets the prefix placed before the Approov token in the token header.
     *
     * @return the prefix, or an empty string if there is none
     */
    public String getTokenHeaderPrefix() {
        return (tokenHeaderPrefix != null) ? tokenHeaderPrefix : "";
    }

    /**
     * Sets the prefix placed before the Approov token in the token header.
     *
     * @param tokenHeaderPrefix the prefix, or null for none
     */
    public void setTokenHeaderPrefix(String tokenHeaderPrefix) {
        this.tokenHeaderPrefix = tokenHeaderPrefix;
    }

    /**
     * Gets the header key used for the optional Approov TraceID debug header.
     *
     * @return the Approov TraceID header key, or null if not used
     */
    public String getTraceIDHeaderKey() {
        return traceIDHeaderKey;
    }

    /**
     * Sets the header key used for the optional Approov TraceID debug header.
     *
     * @param traceIDHeaderKey the Approov TraceID header key
     */
    public void setTraceIDHeaderKey(String traceIDHeaderKey) {
        this.traceIDHeaderKey = traceIDHeaderKey;
    }

    /**
     * Gets the headers whose value was replaced by a secure string. A header whose secure string could not be
     * fetched, and which carries the fetch status instead, is not listed.
     *
     * @return the substituted header names, or null if none
     */
    public List<String> getSubstitutionHeaderKeys() {
        return substitutionHeaderKeys;
    }

    /**
     * Sets the headers whose value was replaced by a secure string.
     *
     * @param substitutionHeaderKeys the substituted header names
     */
    public void setSubstitutionHeaderKeys(List<String> substitutionHeaderKeys) {
        this.substitutionHeaderKeys = substitutionHeaderKeys;
    }

    /**
     * Gets the request URL before any query parameter substitution.
     *
     * @return the URL before substitution, or null if no query parameter was changed
     */
    public String getOriginalURL() {
        return originalURL;
    }

    /**
     * Gets the query parameters whose value was replaced by a secure string. A parameter whose secure string
     * could not be fetched, and which carries the fetch status instead, is not listed.
     *
     * @return the substituted query parameter keys, or null if none
     */
    public List<String> getSubstitutionQueryParamKeys() {
        return substitutionQueryParamKeys;
    }

    /**
     * Sets the URL before any query parameter substitution and the query parameters given a secure string.
     *
     * @param originalURL the URL before substitution
     * @param substitutionQueryParamKeys the substituted query parameter keys
     */
    public void setSubstitutionQueryParamResults(String originalURL, List<String> substitutionQueryParamKeys) {
        this.originalURL = originalURL;
        this.substitutionQueryParamKeys = substitutionQueryParamKeys;
    }

    /**
     * Gets any additional header keys added during request processing.
     *
     * @return list of additional header keys, or null if none were tracked
     */
    public List<String> getAddedHeaderKeys() {
        return addedHeaderKeys;
    }

    /**
     * Sets any additional header keys added during request processing.
     *
     * @param addedHeaderKeys list of added header keys
     */
    public void setAddedHeaderKeys(List<String> addedHeaderKeys) {
        this.addedHeaderKeys = addedHeaderKeys;
    }
}
