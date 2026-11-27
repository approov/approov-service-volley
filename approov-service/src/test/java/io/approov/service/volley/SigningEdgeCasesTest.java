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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.util.Log;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import io.approov.util.volley.sig.ComponentProvider;
import io.approov.util.volley.sig.SignatureParameters;

/**
 * Signing edge cases that must match the OkHttp layer. {@code @query} is the query as sent with its leading
 * {@code ?}, or {@code ?} alone when the URL has none (RFC 9421 section 2.2.7). The only exceptions from
 * building the signature parameters that abort a request are a body digest configured as required that cannot be
 * generated, reported as an ApproovException whose cause is a RequiredBodyDigestException, and an unsupported
 * algorithm; any other exception, from a custom factory included, sends the request unsigned and logs an error,
 * as the backend is the enforcement point.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningEdgeCasesTest {
    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovTestSupport.resetApproovServiceState();
        ShadowLog.reset();
    }

    private static ApproovDefaultMessageSigning.VolleyComponentProvider provider(String url) {
        return new ApproovDefaultMessageSigning.VolleyComponentProvider(
                ApproovTestSupport.request(Request.Method.GET, url, new LinkedHashMap<String, String>(), null, null),
                new LinkedHashMap<String, String>());
    }

    @Test
    public void queryHasItsLeadingQuestionMarkAsSent() {
        assertEquals("?path=color:red|weight:5&q=a%20b&pct=100%25",
                provider("https://maps.example.com/p?path=color:red|weight:5&q=a%20b&pct=100%25#frag").getQuery());
        assertEquals("an empty query", "?", provider("https://example.com/p?").getQuery());
        assertEquals("no query", "?", provider("https://example.com/p").getQuery());
        assertEquals("no query and a fragment", "?", provider("https://example.com/p#frag").getQuery());
    }

    @Test
    public void aSignatureCoveringQueryIsMadeWithoutAQuery() throws Exception {
        SignatureParameters base = new SignatureParameters()
                .addComponentIdentifier(ComponentProvider.DC_METHOD)
                .addComponentIdentifier(ComponentProvider.DC_QUERY);
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(base));
        Map<String, String> signed = sign(signer, ApproovTestSupport.request("https://api.example.com/data"));
        assertNotNull("signed", signed.get("Signature"));
        assertTrue(signed.get("Signature-Input"), signed.get("Signature-Input").contains("\"@query\""));
    }

    // signs a request carrying the token header, returning the resulting headers
    private static Map<String, String> sign(ApproovDefaultMessageSigning signer, Request<?> request)
            throws ApproovException {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        return signer.handleRequestProcessedHeaders(request, headers, changes);
    }

    // the error lines logged by message signing
    private static int signingErrors() {
        int n = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ((item.type == Log.ERROR) && item.msg.startsWith("Message signing"))
                n++;
        }
        return n;
    }

    @Test
    public void aRequiredBodyDigestThatCannotBeGeneratedAbortsWithItsOwnCause() {
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true));
        try {
            sign(signer, ApproovTestSupport.request("https://api.example.com/data"));
            fail("a required body digest that cannot be generated must abort");
        } catch (ApproovException e) {
            assertTrue(String.valueOf(e.getCause()),
                    e.getCause() instanceof ApproovDefaultMessageSigning.RequiredBodyDigestException);
            assertTrue(e.getCause() instanceof IllegalStateException);
        }

        // with a body the digest is generated and the request is signed
        Map<String, String> signed;
        try {
            signed = sign(signer, ApproovTestSupport.request(Request.Method.POST, "https://api.example.com/data",
                    new LinkedHashMap<String, String>(), "a=1".getBytes(StandardCharsets.UTF_8), null));
        } catch (ApproovException e) {
            throw new AssertionError("a body digest that can be generated must not abort", e);
        }
        assertNotNull(signed.get("Content-Digest"));
        assertNotNull(signed.get("Signature"));
    }

    @Test
    public void anyOtherExceptionFromBuildingTheParametersSendsTheRequestUnsigned() throws Exception {
        RuntimeException[] failures = {
                new IllegalStateException("custom factory state"),
                new IllegalArgumentException("custom factory argument"),
                new NullPointerException("custom factory bug")};
        for (RuntimeException failure : failures) {
            ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                    new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                        @Override
                        protected SignatureParameters buildSignatureParameters(
                                ApproovDefaultMessageSigning.VolleyComponentProvider provider,
                                ApproovRequestMutations changes) {
                            throw failure;
                        }
                    };
            ShadowLog.reset();
            Map<String, String> headers = sign(new ApproovDefaultMessageSigning().setDefaultFactory(factory),
                    ApproovTestSupport.request("https://api.example.com/data"));
            assertNull(failure.toString(), headers.get("Signature"));
            assertNull(failure.toString(), headers.get("Signature-Input"));
            assertEquals(failure.toString(), "t", headers.get("Approov-Token"));
            assertEquals(failure.toString(), 1, signingErrors());
        }

        // a subclass overriding buildSignatureParameters is treated the same way
        ApproovDefaultMessageSigning subclass = new ApproovDefaultMessageSigning() {
            @Override
            protected SignatureParameters buildSignatureParameters(VolleyComponentProvider provider,
                    ApproovRequestMutations changes) {
                throw new IllegalStateException("subclass failure");
            }
        }.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        ShadowLog.reset();
        Map<String, String> headers = sign(subclass, ApproovTestSupport.request("https://api.example.com/data"));
        assertNull(headers.get("Signature"));
        assertEquals(1, signingErrors());
        assertFalse(headers.containsKey("Signature-Input"));
    }

    @Test
    public void aRequiredBodyDigestFailureReachesTheAppWithItsCauseThroughTheStack() throws Exception {
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(
                java.util.Collections.singletonMap("api.example.com", java.util.Collections.<String>emptyList()));
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt", "", "trace", false);
        approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/data")).thenReturn(success);
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true)));
        ApproovHurlStack stack = new ApproovHurlStack() {
            @Override
            protected com.android.volley.toolbox.HttpResponse executeNetworkRequest(Request<?> request,
                    Map<String, String> headers) {
                throw new AssertionError("nothing may be sent");
            }
        };
        try {
            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/data"), new LinkedHashMap<>());
            fail("must abort");
        } catch (ApproovException e) {
            // a signing decision keeps its own form rather than being reported as a failing mutator hook
            assertFalse(e.getMessage(), e.getMessage().startsWith("ApproovServiceMutator."));
            assertSame(ApproovDefaultMessageSigning.RequiredBodyDigestException.class, e.getCause().getClass());
        }
    }
}
