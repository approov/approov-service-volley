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
import static org.junit.Assert.fail;

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

import java.util.Collections;
import java.util.Map;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The body the layer signs is the body Volley's HurlStack sends. HurlStack writes a body for POST, PUT and PATCH,
 * and for DEPRECATED_GET_OR_POST when getPostBody has one. A GET, DELETE, HEAD, OPTIONS or TRACE request whose
 * getParams or getBody gives bytes is sent without a body, so it gets no Content-Digest.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class BodySent370Test {
    private MiniSdkHttpsOrigins origins;

    // a request whose body is the default one built from getParams
    private static final class ParamsRequest extends Request<String> {
        ParamsRequest(int method, String url) {
            super(method, url, null);
        }

        @Override
        protected Map<String, String> getParams() {
            return Collections.singletonMap("key", "value");
        }

        @Override
        protected Response<String> parseNetworkResponse(NetworkResponse response) {
            return Response.success("", null);
        }

        @Override
        protected void deliverResponse(String response) {
        }
    }

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private RecordedRequest deliver(Request<?> request) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(request).getStatusCode());
        return origins.take(origins.first);
    }

    private static void assertSignedWithoutDigest(String what, RecordedRequest recorded) {
        assertEquals(what + ": no body is sent", 0, recorded.getBodySize());
        assertNull(what + ": no Content-Digest", recorded.getHeader("Content-Digest"));
        String input = recorded.getHeader("Signature-Input");
        assertNotNull(what + ": the request is signed", input);
        assertFalse(what + ": the signature does not cover content-digest",
                input.toLowerCase().contains("content-digest"));
    }

    @Test
    public void deleteWithParamsSendsNoBodyAndNoDigest() throws Exception {
        RecordedRequest recorded = deliver(new ParamsRequest(Request.Method.DELETE, origins.firstUrl("/d")));
        assertEquals("DELETE", recorded.getMethod());
        assertSignedWithoutDigest("DELETE with getParams", recorded);
    }

    @Test
    public void getWithBodySendsNoBodyAndNoDigest() throws Exception {
        MiniSdkHttpsOrigins.AppRequest request = new MiniSdkHttpsOrigins.AppRequest(Request.Method.GET,
                origins.firstUrl("/g"), null, "payload".getBytes("UTF-8"));
        RecordedRequest recorded = deliver(request);
        assertEquals("GET", recorded.getMethod());
        assertSignedWithoutDigest("GET with getBody", recorded);
    }

    @Test
    public void headOptionsAndTraceSendNoBodyAndNoDigest() throws Exception {
        for (int method : new int[]{Request.Method.HEAD, Request.Method.OPTIONS, Request.Method.TRACE}) {
            RecordedRequest recorded = deliver(new MiniSdkHttpsOrigins.AppRequest(method, origins.firstUrl("/m"),
                    null, "payload".getBytes("UTF-8")));
            assertSignedWithoutDigest("method " + method, recorded);
        }
    }

    @Test
    public void postStillGetsTheDigestOfItsBody() throws Exception {
        RecordedRequest recorded = deliver(new ParamsRequest(Request.Method.POST, origins.firstUrl("/p")));
        assertEquals("key=value&", recorded.getBody().readUtf8());
        // the SHA-256 of "key=value&", as Volley encodes the params
        String digest = recorded.getHeader("Content-Digest");
        assertNotNull(digest);
        assertEquals("sha-256=:" + sha256Base64("key=value&") + ":", digest);
        assertTrue(recorded.getHeader("Signature-Input").toLowerCase().contains("content-digest"));
    }

    @Test
    public void putStillGetsADigest() throws Exception {
        // PATCH is left out: the JVM's HttpURLConnection refuses the method, which Android's accepts
        RecordedRequest recorded = deliver(new ParamsRequest(Request.Method.PUT, origins.firstUrl("/b")));
        assertEquals("key=value&", recorded.getBody().readUtf8());
        assertNotNull(recorded.getHeader("Content-Digest"));
    }

    @Test
    public void requiredDigestOnABodilessDeleteBehavesAsForNoBody() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig("sha-256", true)));
        int before = origins.first.getRequestCount();
        Exception withParams = null;
        Exception withoutBody = null;
        try {
            origins.send(new ParamsRequest(Request.Method.DELETE, origins.firstUrl("/r")));
        } catch (Exception e) {
            withParams = e;
        }
        try {
            origins.send(new MiniSdkHttpsOrigins.AppRequest(Request.Method.DELETE, origins.firstUrl("/r"), null,
                    null));
        } catch (Exception e) {
            withoutBody = e;
        }
        if (withoutBody == null)
            fail("a required digest with no body must fail");
        assertNotNull("a DELETE sends no body, so a required digest fails as for no body", withParams);
        assertEquals(withoutBody.getClass(), withParams.getClass());
        assertEquals(withoutBody.getMessage(), withParams.getMessage());
        assertEquals("nothing was sent", before, origins.first.getRequestCount());
    }

    private static String sha256Base64(String text) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(text.getBytes("UTF-8"));
        return java.util.Base64.getEncoder().encodeToString(digest);
    }
}
