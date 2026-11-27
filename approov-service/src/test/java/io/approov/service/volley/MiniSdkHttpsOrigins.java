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

import static org.junit.Assert.assertNull;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.BasicNetwork;
import com.android.volley.toolbox.HttpResponse;
import com.criticalblue.minisdk.testing.AttesterProxyController;

import java.io.InputStream;
import java.net.InetAddress;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

/**
 * Two local origins for request path tests through the Volley stack: {@code first} is HTTPS on localhost and
 * {@code second} listens on 127.0.0.1, over HTTPS or, when asked, cleartext HTTP. A redirect from one to the
 * other crosses origins. The platform trust (the default SSL socket factory of HttpsURLConnection) trusts
 * both servers for the life of the fixture. The layer is initialized with Approov protection against the
 * mini-SDK as a new process would, so no initialize comment is needed.
 */
final class MiniSdkHttpsOrigins {
    static final String CONFIG = "#test-account#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=";

    // the headers the layer may add, and the removed status header so that it never reappears
    static final String[] APPROOV_HEADERS = {
            "Approov-Token", "Approov-TraceID", "Approov-Status",
            "Signature", "Signature-Input", "Content-Digest"
    };

    final Context context = ApplicationProvider.getApplicationContext();
    final MockWebServer first = new MockWebServer();
    final MockWebServer second = new MockWebServer();
    private final SSLSocketFactory previousFactory;

    MiniSdkHttpsOrigins(boolean secondOverTls) throws Exception {
        HeldCertificate certificate = new HeldCertificate.Builder()
                .addSubjectAlternativeName("localhost")
                .addSubjectAlternativeName("127.0.0.1")
                .build();
        HandshakeCertificates serverHandshake = new HandshakeCertificates.Builder()
                .heldCertificate(certificate)
                .build();
        first.useHttps(serverHandshake.sslSocketFactory(), false);
        first.start(InetAddress.getByName("localhost"), 0);
        if (secondOverTls)
            second.useHttps(serverHandshake.sslSocketFactory(), false);
        second.start(InetAddress.getByName("127.0.0.1"), 0);
        HandshakeCertificates clientHandshake = new HandshakeCertificates.Builder()
                .addTrustedCertificate(certificate.certificate())
                .build();
        previousFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(clientHandshake.sslSocketFactory());
    }

    /** A URL on the first origin, https://localhost:port/path. */
    String firstUrl(String path) {
        return first.url(path).toString();
    }

    /** A URL on the second origin, named by its IP address. */
    String secondUrl(String path) {
        return second.url(path).newBuilder().host("127.0.0.1").build().toString();
    }

    /**
     * Initializes the layer with Approov protection, as the first initialization of a new process, with the
     * given mini-SDK hook installed.
     */
    <T extends MiniSdkHook> T initialize(T hook) {
        AttesterProxyController.reset();
        AttesterProxyController.loadScenarioJson("{\"activeCase\": \"origins\", \"cases\": {\"origins\": {"
                + "\"protectedDomains\": [\"localhost\"],"
                + "\"pins\": {\"public-key-sha256\": {\"localhost\": []}}}}}");
        AttesterProxyController.resetSdkForTesting();
        MiniSdkHook.install(hook);
        ApproovService.reset();
        ApproovService.initialize(context, CONFIG, null);
        return hook;
    }

    /** Sends a request through the Approov stack and returns the response with its body read. */
    HttpResponse send(Request<?> request) throws Exception {
        HttpResponse response = ApproovService.getBaseHttpStack().executeRequest(request,
                Collections.<String, String>emptyMap());
        InputStream content = response.getContent();
        if (content != null)
            content.close();
        return response;
    }

    /**
     * Performs a request as a Volley RequestQueue does, through BasicNetwork, and returns the error the app
     * would receive, or null if the request succeeded.
     */
    VolleyError perform(Request<?> request) {
        try {
            new BasicNetwork(ApproovService.getBaseHttpStack()).performRequest(request);
            return null;
        } catch (VolleyError e) {
            return e;
        }
    }

    RecordedRequest take(MockWebServer server) throws Exception {
        return server.takeRequest(5, TimeUnit.SECONDS);
    }

    static MockResponse ok() {
        return new MockResponse().setBody("ok");
    }

    static void assertNoApproovHeaders(String what, RecordedRequest recorded) {
        for (String header : APPROOV_HEADERS)
            assertNull(what + ": " + header + " must not be sent", recorded.getHeader(header));
    }

    void shutdown() throws Exception {
        HttpsURLConnection.setDefaultSSLSocketFactory(previousFactory);
        first.shutdown();
        second.shutdown();
        MiniSdkHook.uninstall();
        AttesterProxyController.reset();
        AttesterProxyController.resetSdkForTesting();
        ApproovService.reset();
    }

    /** A Volley request with app headers, an optional body and the method given. */
    static final class AppRequest extends Request<String> {
        private final Map<String, String> headers;
        private final byte[] body;
        int getHeadersCalls;

        AppRequest(int method, String url, Map<String, String> headers, byte[] body) {
            super(method, url, null);
            this.headers = (headers == null) ? new LinkedHashMap<String, String>() : new LinkedHashMap<>(headers);
            this.body = body;
        }

        AppRequest(String url) {
            this(Method.GET, url, null, null);
        }

        AppRequest header(String name, String value) {
            headers.put(name, value);
            return this;
        }

        @Override
        public Map<String, String> getHeaders() {
            getHeadersCalls++;
            return new LinkedHashMap<>(headers);
        }

        @Override
        public byte[] getBody() {
            return body;
        }

        @Override
        protected Response<String> parseNetworkResponse(NetworkResponse response) {
            return Response.success(new String(response.data), null);
        }

        @Override
        protected void deliverResponse(String response) {
        }
    }
}
