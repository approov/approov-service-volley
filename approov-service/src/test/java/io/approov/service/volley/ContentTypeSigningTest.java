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
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Content-Type is signed as HurlStack sends it. For a request it sends with a body (POST, PUT and PATCH with a
 * body, and DEPRECATED_GET_OR_POST with a post body), HurlStack sets Content-Type to getBodyContentType() unless
 * the headers it is given already hold one. Android's HttpURLConnection finds a header without regard to the
 * case of its name, so a Content-Type the app gives in getHeaders(), in any case, takes precedence. The view of
 * the request holds that one header, so the signature covers the value on the wire. Content-Length is never a
 * covered component, as the platform sets it after signing.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ContentTypeSigningTest {
    private static final String JSON = "application/json; charset=utf-8";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovTestSupport.resetApproovServiceState();
    }

    /** A request with a post body for DEPRECATED_GET_OR_POST. */
    private static final class PostBodyRequest extends Request<String> {
        private final byte[] postBody;

        @SuppressWarnings("deprecation")
        PostBodyRequest(byte[] postBody) {
            super(Request.Method.DEPRECATED_GET_OR_POST, "https://h/p", null);
            this.postBody = postBody;
        }

        @Override
        @SuppressWarnings("deprecation")
        public byte[] getPostBody() {
            return postBody;
        }

        @Override
        public String getBodyContentType() {
            return JSON;
        }

        @Override
        protected com.android.volley.Response<String> parseNetworkResponse(com.android.volley.NetworkResponse r) {
            return null;
        }

        @Override
        protected void deliverResponse(String response) {
        }
    }

    private static Map<String, String> headers(String... nameValues) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 0; i < nameValues.length; i += 2)
            headers.put(nameValues[i], nameValues[i + 1]);
        return headers;
    }

    // the headers HurlStack is given for a request: the view of it with the app's headers
    private static Map<String, String> viewHeaders(Request<?> request, Map<String, String> appHeaders)
            throws Exception {
        return ApproovRequestView.of(request, appHeaders).getHeaders();
    }

    private static Request<?> request(int method, byte[] body, Map<String, String> appHeaders) {
        return ApproovTestSupport.request(method, "https://h/p", appHeaders, body, JSON);
    }

    @Test
    public void aRequestSentWithABodyHasTheContentTypeHurlStackSets() throws Exception {
        byte[] body = ApproovTestSupport.utf8("{}");
        for (int method : new int[]{Request.Method.POST, Request.Method.PUT, Request.Method.PATCH}) {
            Map<String, String> sent = viewHeaders(request(method, body, null), headers());
            assertEquals("method " + method, Collections.singletonMap("Content-Type", JSON), sent);
        }
        // an empty body is still a body
        assertEquals(JSON, viewHeaders(request(Request.Method.POST, new byte[0], null), headers()).get("Content-Type"));
        assertEquals(JSON, viewHeaders(new PostBodyRequest(body), headers()).get("Content-Type"));
    }

    @Test
    public void aRequestSentWithoutABodyHasNoContentType() throws Exception {
        byte[] body = ApproovTestSupport.utf8("{}");
        for (int method : new int[]{Request.Method.GET, Request.Method.DELETE, Request.Method.HEAD,
                Request.Method.OPTIONS, Request.Method.TRACE})
            assertTrue("method " + method, viewHeaders(request(method, body, null), headers()).isEmpty());
        // HurlStack adds no body, and so no Content-Type, for a null body
        assertTrue(viewHeaders(request(Request.Method.POST, null, null), headers()).isEmpty());
        assertTrue(viewHeaders(new PostBodyRequest(null), headers()).isEmpty());
    }

    @Test
    public void theAppsContentTypeInAnyCaseTakesPrecedence() throws Exception {
        byte[] body = ApproovTestSupport.utf8("{}");
        for (String name : new String[]{"Content-Type", "content-type", "CONTENT-TYPE"}) {
            Map<String, String> sent = viewHeaders(request(Request.Method.POST, body, null),
                    headers("X-App", "1", name, "text/plain"));
            // one Content-Type, named so that HurlStack finds it and keeps it
            assertEquals(name, headers("X-App", "1", "Content-Type", "text/plain"), sent);
        }
    }

    // signs the view of a request with the factory and returns the signed headers and the install signature base
    private String[] sign(ApproovDefaultMessageSigning.SignatureParametersFactory factory, Request<?> request,
            Map<String, String> appHeaders) throws Exception {
        approov.clearInvocations();
        Map<String, String> headers = headers("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        Map<String, String> signed = new ApproovDefaultMessageSigning().setDefaultFactory(factory)
                .handleRequestProcessedHeaders(ApproovRequestView.of(request, appHeaders), headers, changes);
        assertNotNull(signed.get("Signature"));
        ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(base.capture()));
        return new String[]{signed.get("Signature-Input"), base.getValue()};
    }

    @Test
    public void theDefaultFactoryCoversTheContentTypeSent() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
        String[] post = sign(factory, request(Request.Method.POST, ApproovTestSupport.utf8("{}"), null), headers());
        assertTrue(post[0], post[0].contains("\"content-type\""));
        assertTrue(post[1], post[1].contains("\"content-type\": " + JSON + "\n"));

        String[] get = sign(factory, request(Request.Method.GET, null, null), headers());
        assertFalse(get[0], get[0].contains("\"content-type\""));
    }

    @Test
    public void anOptionalContentTypeHeaderIsCoveredTheSameWay() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                new ApproovDefaultMessageSigning.SignatureParametersFactory()
                        .setBaseParameters(new io.approov.util.volley.sig.SignatureParameters()
                                .addComponentIdentifier(io.approov.util.volley.sig.ComponentProvider.DC_METHOD))
                        .setUseInstallMessageSigning()
                        .addOptionalHeaders("content-type");
        String[] post = sign(factory, request(Request.Method.POST, ApproovTestSupport.utf8("a=1"), null), headers());
        assertTrue(post[1], post[1].contains("\"content-type\": " + JSON + "\n"));
        String[] app = sign(factory, request(Request.Method.PUT, ApproovTestSupport.utf8("a=1"), null),
                headers("content-type", "text/plain"));
        assertTrue(app[1], app[1].contains("\"content-type\": text/plain\n"));
        String[] get = sign(factory, request(Request.Method.GET, null, null), headers());
        assertFalse(get[0], get[0].contains("\"content-type\""));
    }

    @Test
    public void contentLengthIsNeverCovered() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .addOptionalHeaders("Content-Length");
        String[] post = sign(factory, request(Request.Method.POST, ApproovTestSupport.utf8("{}"), null),
                headers("Content-Length", "2"));
        assertFalse(post[0], post[0].contains("\"content-length\""));
        assertFalse(post[1], post[1].contains("\"content-length\""));
    }
}
