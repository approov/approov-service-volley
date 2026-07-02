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
    private String traceIDHeaderKey;
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
