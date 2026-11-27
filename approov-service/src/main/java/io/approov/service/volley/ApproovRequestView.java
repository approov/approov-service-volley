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

import okhttp3.HttpUrl;

/**
 * A view of one network attempt of an app's Volley request: the URL, method, body and headers it is sent with.
 * The headers and body are read from the app's request once, so that the message signature and any body digest
 * cover exactly what is sent, even if getHeaders() or getBody() give a new value on every call. The URL is in
 * the form that Android sends (see wireUrl), so that HurlStack opens the connection for the URL that is signed,
 * and the headers include the Content-Type that HurlStack sends with a body (see sentHeaders). Everything else,
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
        this.headers = sentHeaders(original, method, body, headers);
    }

    /**
     * Gets the headers HurlStack sends for an attempt. For a request it sends with a body (POST, PUT or PATCH
     * with a body that is not null), HurlStack sets Content-Type to getBodyContentType() unless the headers it is
     * given already hold one. Android's HttpURLConnection finds that header without regard to the case of its
     * name, so a Content-Type the app gives, in any case, takes precedence. The headers hold the one Content-Type
     * that is sent, named "Content-Type" so that HurlStack finds it on any platform, and the message signature
     * covers the value on the wire. A null body content type is not sent, as HttpURLConnection ignores a header
     * with a null value.
     *
     * @param original is the app's request
     * @param method is the method of the attempt
     * @param body is the body of the attempt, or null for none
     * @param headers are the headers of the attempt
     * @return the headers sent
     */
    private static Map<String, String> sentHeaders(Request<?> original, int method, byte[] body,
            Map<String, String> headers) {
        Map<String, String> sent = new LinkedHashMap<>(headers);
        if (!sendsBody(method) || (body == null))
            return sent;
        String contentType = ApproovHurlStack.header(sent, "Content-Type");
        ApproovHurlStack.removeHeader(sent, "Content-Type");
        if (contentType == null)
            contentType = original.getBodyContentType();
        if (contentType != null)
            sent.put("Content-Type", contentType);
        return sent;
    }

    /**
     * Reads an app's request once. A DEPRECATED_GET_OR_POST request is given the method HurlStack sends it with,
     * POST if it has a body and GET otherwise. The body is the one HurlStack sends, which is none for any
     * method but POST, PUT and PATCH.
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
        } else if (sendsBody(method)) {
            body = request.getBody();
        } else {
            // the stack sends no body for any other method, so none is read, signed or digested
            body = null;
        }
        return new ApproovRequestView(request, sentUrl(request.getUrl()), method, body, headers);
    }

    /**
     * Gets a URL in the form that Android sends it. Android's HttpURLConnection parses the URL with OkHttp's
     * HttpUrl and writes the request line from the result, so a character it does not send as written, such as
     * "|" or a space in the path, or a character that is not ASCII, is percent-encoded, while an existing escape
     * stays as it is. The scheme and host are in lowercase, and a default port is left out. The fragment is left
     * out too, as it is never sent. Parsing the result again gives the same URL.
     *
     * @param url is the URL as the app wrote it
     * @return the URL as Android sends it, or null if HttpUrl cannot parse it, which Android would also reject
     */
    static String wireUrl(String url) {
        HttpUrl parsed = parseWireUrl(url);
        return (parsed != null) ? parsed.toString() : null;
    }

    /**
     * Parses a URL as Android does before it sends a request, without the fragment.
     *
     * @param url is the URL as the app wrote it
     * @return the parsed URL without any fragment, or null if HttpUrl cannot parse it
     */
    static HttpUrl parseWireUrl(String url) {
        if (url == null)
            return null;
        HttpUrl parsed;
        try {
            parsed = HttpUrl.parse(url);
        } catch (RuntimeException e) {
            return null;
        }
        if ((parsed != null) && (parsed.encodedFragment() != null))
            parsed = parsed.newBuilder().fragment(null).build();
        return parsed;
    }

    // gets the URL an attempt is sent with: the form Android sends, or the URL as written if HttpUrl cannot
    // parse it, as the request is then sent as written and unsigned
    private static String sentUrl(String url) {
        String wire = wireUrl(url);
        return (wire != null) ? wire : url;
    }

    /**
     * Tells whether HurlStack writes the body of a request with the method. It does for POST, PUT and PATCH only.
     * GET, DELETE, HEAD, OPTIONS and TRACE go without a body, even if getBody gives one.
     *
     * @param method is the method of the request
     * @return true if the method is sent with a body
     */
    private static boolean sendsBody(int method) {
        return (method == Method.POST) || (method == Method.PUT) || (method == Method.PATCH);
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
     * Gets a view of another attempt of the same app request, with the URL in the form Android sends.
     *
     * @param newUrl is the URL of the attempt
     * @param newMethod is the method of the attempt
     * @param newBody is the body of the attempt, or null for none
     * @param newHeaders are the headers of the attempt
     * @return the new view
     */
    ApproovRequestView attempt(String newUrl, int newMethod, byte[] newBody, Map<String, String> newHeaders) {
        return new ApproovRequestView(original, sentUrl(newUrl), newMethod, newBody, newHeaders);
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
