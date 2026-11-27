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
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
import com.android.volley.RetryPolicy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A view of one network attempt of an app's Volley request: the URL, method, body and headers it is sent with.
 * The headers and body are read from the app's request once, so that the message signature and any body digest
 * cover exactly what is sent, even if getHeaders() or getBody() give a new value on every call. Everything else,
 * such as the retry policy that sets the timeouts, is the app's request's own. A view is never added to a
 * RequestQueue and never parses or delivers a response.
 */
final class ApproovRequestView extends Request<Object> {
    // the app's request
    private final Request<?> original;

    // the URL, method, body and headers of this attempt
    private final String url;
    private final int method;
    private final byte[] body;
    private final Map<String, String> headers;

    private ApproovRequestView(Request<?> original, String url, int method, byte[] body, Map<String, String> headers) {
        super(method, url, null);
        this.original = original;
        this.url = url;
        this.method = method;
        this.body = body;
        this.headers = new LinkedHashMap<>(headers);
    }

    /**
     * Reads an app's request once. A DEPRECATED_GET_OR_POST request is given the method HurlStack sends it with,
     * POST if it has a body and GET otherwise.
     *
     * @param request is the app's request
     * @param headers are the headers of the attempt
     * @return the view of the request
     * @throws AuthFailureError if the request's body cannot be read
     */
    static ApproovRequestView of(Request<?> request, Map<String, String> headers) throws AuthFailureError {
        if (request instanceof ApproovRequestView)
            return ((ApproovRequestView) request).withHeaders(headers);
        int method = request.getMethod();
        byte[] body;
        if (method == Method.DEPRECATED_GET_OR_POST) {
            @SuppressWarnings("deprecation")
            byte[] postBody = request.getPostBody();
            body = postBody;
            method = (body != null) ? Method.POST : Method.GET;
        } else {
            body = request.getBody();
        }
        return new ApproovRequestView(request, request.getUrl(), method, body, headers);
    }

    /**
     * Gets a view of the same attempt with other headers.
     *
     * @param newHeaders are the headers
     * @return the new view
     */
    ApproovRequestView withHeaders(Map<String, String> newHeaders) {
        return new ApproovRequestView(original, url, method, body, newHeaders);
    }

    /**
     * Gets a view of another attempt of the same app request.
     *
     * @param newUrl is the URL of the attempt
     * @param newMethod is the method of the attempt
     * @param newBody is the body of the attempt, or null for none
     * @param newHeaders are the headers of the attempt
     * @return the new view
     */
    ApproovRequestView attempt(String newUrl, int newMethod, byte[] newBody, Map<String, String> newHeaders) {
        return new ApproovRequestView(original, newUrl, newMethod, newBody, newHeaders);
    }

    /**
     * Gets the app's request this is a view of.
     *
     * @return the app's request
     */
    Request<?> getOriginal() {
        return original;
    }

    @Override
    public String getUrl() {
        return url;
    }

    @Override
    public int getMethod() {
        return method;
    }

    @Override
    public Map<String, String> getHeaders() {
        return new LinkedHashMap<>(headers);
    }

    @Override
    public byte[] getBody() {
        return body;
    }

    @Override
    @SuppressWarnings("deprecation")
    public byte[] getPostBody() {
        return body;
    }

    @Override
    public String getBodyContentType() {
        return original.getBodyContentType();
    }

    @Override
    public RetryPolicy getRetryPolicy() {
        return original.getRetryPolicy();
    }

    @Override
    public int getTrafficStatsTag() {
        return original.getTrafficStatsTag();
    }

    @Override
    public Object getTag() {
        return original.getTag();
    }

    @Override
    public boolean isCanceled() {
        return original.isCanceled();
    }

    @Override
    public Priority getPriority() {
        return original.getPriority();
    }

    @Override
    protected Response<Object> parseNetworkResponse(NetworkResponse response) {
        throw new UnsupportedOperationException("ApproovRequestView never parses a response");
    }

    @Override
    protected void deliverResponse(Object response) {
        throw new UnsupportedOperationException("ApproovRequestView never delivers a response");
    }
}
