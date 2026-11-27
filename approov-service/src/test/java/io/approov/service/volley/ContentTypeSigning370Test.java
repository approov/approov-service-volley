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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import io.approov.util.volley.sig.ComponentProvider;
import io.approov.util.volley.sig.SignatureParameters;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Content-Type on the wire: for a request sent with a body the signature covers the Content-Type header the
 * server receives, which is getBodyContentType() or, if the app gives one in getHeaders(), the app's value,
 * and the install signature verifies over it. A request sent without a body does not cover it.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ContentTypeSigning370Test {
    private MiniSdkHttpsOrigins origins;
    private String origin;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost", "127.0.0.1");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        useFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        origin = "https://localhost:" + origins.first.getPort();
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private static void useFactory(ApproovDefaultMessageSigning.SignatureParametersFactory factory) {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory));
    }

    /** A Volley request with a body, a body content type and app headers. */
    private static final class BodyRequest extends Request<String> {
        private final byte[] body;
        private final String contentType;
        private final Map<String, String> headers = new LinkedHashMap<>();

        BodyRequest(int method, String url, String body, String contentType) {
            super(method, url, null);
            this.body = (body != null) ? body.getBytes(StandardCharsets.UTF_8) : null;
            this.contentType = contentType;
        }

        BodyRequest header(String name, String value) {
            headers.put(name, value);
            return this;
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
        public String getBodyContentType() {
            return (contentType != null) ? contentType : super.getBodyContentType();
        }

        @Override
        protected Response<String> parseNetworkResponse(NetworkResponse response) {
            return Response.success(new String(response.data, StandardCharsets.UTF_8), null);
        }

        @Override
        protected void deliverResponse(String response) {
        }
    }

    private RecordedRequest send(Request<?> request) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull(recorded);
        return recorded;
    }

    // checks that the request covers the Content-Type it was sent with, whose value is given
    private void assertContentTypeCovered(String what, String expected, RecordedRequest recorded) throws Exception {
        assertEquals(what, expected, recorded.getHeader("Content-Type"));
        assertTrue(what + ": " + recorded.getHeader("Signature-Input"),
                recorded.getHeader("Signature-Input").contains("\"content-type\""));
        String base = WireUrlSigning370Test.verifyInstallSignature(origin, recorded);
        assertTrue(what + ": " + base, base.contains("\"content-type\": " + expected + "\n"));
    }

    @Test
    public void aJsonPostCoversItsContentType() throws Exception {
        RecordedRequest recorded = send(new BodyRequest(Request.Method.POST, origin + "/json", "{\"a\":1}",
                "application/json; charset=utf-8"));
        assertContentTypeCovered("JSON POST", "application/json; charset=utf-8", recorded);
    }

    @Test
    public void aFormPostCoversItsContentType() throws Exception {
        // Volley's own body content type for a form
        RecordedRequest recorded = send(new BodyRequest(Request.Method.POST, origin + "/form", "a=1&b=2", null));
        assertContentTypeCovered("form POST", "application/x-www-form-urlencoded; charset=UTF-8", recorded);
    }

    @Test
    public void aGetDoesNotCoverContentType() throws Exception {
        RecordedRequest recorded = send(new BodyRequest(Request.Method.GET, origin + "/get", null, null));
        assertNull(recorded.getHeader("Content-Type"));
        assertFalse(recorded.getHeader("Signature-Input"),
                recorded.getHeader("Signature-Input").contains("\"content-type\""));
        WireUrlSigning370Test.verifyInstallSignature(origin, recorded);
    }

    @Test
    public void theAppsContentTypeTakesPrecedenceInAnyCase() throws Exception {
        for (String name : new String[]{"Content-Type", "content-type"}) {
            RecordedRequest recorded = send(new BodyRequest(Request.Method.POST, origin + "/app", "{}",
                    "application/json; charset=utf-8").header(name, "text/plain; charset=utf-8"));
            assertContentTypeCovered(name, "text/plain; charset=utf-8", recorded);
        }
    }

    @Test
    public void anOptionalContentTypeHeaderIsCoveredTheSameWay() throws Exception {
        useFactory(new ApproovDefaultMessageSigning.SignatureParametersFactory()
                .setBaseParameters(new SignatureParameters()
                        .addComponentIdentifier(ComponentProvider.DC_METHOD)
                        .addComponentIdentifier(ComponentProvider.DC_TARGET_URI))
                .setUseInstallMessageSigning()
                .setAddApproovTokenHeader(true)
                .addOptionalHeaders("content-type"));
        RecordedRequest put = send(new BodyRequest(Request.Method.PUT, origin + "/put", "{}",
                "application/json; charset=utf-8"));
        assertContentTypeCovered("PUT", "application/json; charset=utf-8", put);
        RecordedRequest get = send(new BodyRequest(Request.Method.GET, origin + "/get", null, null));
        assertFalse(get.getHeader("Signature-Input").contains("\"content-type\""));
    }

    // the quoted component identifiers of a Signature-Input value, in order
    private static java.util.List<String> components(String signatureInput) {
        java.util.List<String> found = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"([^\"]+)\"").matcher(signatureInput);
        while (m.find()) {
            found.add(m.group(1));
        }
        return found;
    }

    @Test
    public void aRepeatedOptionalHeaderIsCoveredOnce() throws Exception {
        useFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                .addOptionalHeaders("Content-Type", "content-type", "Authorization"));
        RecordedRequest recorded = send(new BodyRequest(Request.Method.POST, origin + "/dup", "{}",
                "application/json; charset=utf-8").header("Authorization", "Bearer abc"));
        java.util.List<String> covered = components(recorded.getHeader("Signature-Input"));
        assertEquals(recorded.getHeader("Signature-Input"), 1, java.util.Collections.frequency(covered, "content-type"));
        assertEquals(recorded.getHeader("Signature-Input"), 1, java.util.Collections.frequency(covered, "authorization"));
        assertEquals(new java.util.LinkedHashSet<>(covered).size(), covered.size());
        // the default factory adds Authorization, then Content-Type; the repeats change nothing
        assertTrue(covered.indexOf("authorization") < covered.indexOf("content-type"));
        WireUrlSigning370Test.verifyInstallSignature(origin, recorded);
    }

    @Test
    public void aBaseComponentAddedAgainIsCoveredOnce() throws Exception {
        useFactory(new ApproovDefaultMessageSigning.SignatureParametersFactory()
                .setBaseParameters(new SignatureParameters()
                        .addComponentIdentifier(ComponentProvider.DC_METHOD)
                        .addComponentIdentifier(ComponentProvider.DC_TARGET_URI)
                        .addComponentIdentifier("Content-Type"))
                .setUseInstallMessageSigning()
                .setAddApproovTokenHeader(true)
                .addOptionalHeaders("content-type"));
        RecordedRequest recorded = send(new BodyRequest(Request.Method.POST, origin + "/base", "{}",
                "application/json; charset=utf-8"));
        java.util.List<String> covered = components(recorded.getHeader("Signature-Input"));
        assertEquals(recorded.getHeader("Signature-Input"), 1, java.util.Collections.frequency(covered, "content-type"));
        assertEquals(new java.util.LinkedHashSet<>(covered).size(), covered.size());
        WireUrlSigning370Test.verifyInstallSignature(origin, recorded);
    }
}
