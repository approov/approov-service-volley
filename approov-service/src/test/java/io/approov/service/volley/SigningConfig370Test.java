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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.security.MessageDigest;
import java.util.Base64;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The signature configuration seen on the wire: the Signature and Content-Digest values are Byte Sequences
 * (base64 between colons, never a quoted string), a covered header with an empty value is a valid component,
 * and the body digest can use SHA-256 or SHA-512, be disabled, or be required of a request that has a body.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningConfig370Test {
    private static final String BASE64 = "[A-Za-z0-9+/]+=*";

    private MiniSdkHttpsOrigins origins;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private static ApproovDefaultMessageSigning.SignatureParametersFactory factory() {
        return ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
    }

    private RecordedRequest deliver(ApproovDefaultMessageSigning.SignatureParametersFactory factory,
            MiniSdkHttpsOrigins.AppRequest request) throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(factory));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    private MiniSdkHttpsOrigins.AppRequest post(byte[] body) {
        return new MiniSdkHttpsOrigins.AppRequest(Request.Method.POST, origins.firstUrl("/post"), null, body);
    }

    private static String digest(String algorithm, String text) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance(algorithm).digest(text.getBytes("UTF-8")));
    }

    @Test
    public void theSignatureAndTheDigestAreByteSequences() throws Exception {
        RecordedRequest recorded = deliver(factory().setUseInstallAndAccountMessageSigning(), post("body".getBytes("UTF-8")));
        String signature = recorded.getHeader("Signature");
        assertTrue(signature, signature.matches("install=:" + BASE64 + ":, account=:" + BASE64 + ":"));
        assertFalse(signature, signature.contains("\""));
        assertEquals("sha-256=:" + digest("SHA-256", "body") + ":", recorded.getHeader("Content-Digest"));
    }

    @Test
    public void aCoveredHeaderWithAnEmptyValueIsSigned() throws Exception {
        RecordedRequest recorded = deliver(factory().addOptionalHeaders("X-Empty"),
                new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/e")).header("X-Empty", ""));
        assertNotNull("the request is signed", recorded.getHeader("Signature"));
        assertTrue(recorded.getHeader("Signature-Input"), recorded.getHeader("Signature-Input").contains("\"x-empty\""));
    }

    @Test
    public void theDigestCanUseSha512() throws Exception {
        RecordedRequest recorded = deliver(factory().setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA512, false),
                post("body".getBytes("UTF-8")));
        assertEquals("sha-512=:" + digest("SHA-512", "body") + ":", recorded.getHeader("Content-Digest"));
        assertTrue(recorded.getHeader("Signature-Input").contains("\"content-digest\""));
    }

    @Test
    public void aDisabledDigestSignsWithoutOne() throws Exception {
        RecordedRequest recorded = deliver(factory().setBodyDigestConfig(null, true), post("body".getBytes("UTF-8")));
        assertNull(recorded.getHeader("Content-Digest"));
        assertNotNull(recorded.getHeader("Signature"));
        assertFalse(recorded.getHeader("Signature-Input").contains("content-digest"));
    }

    @Test
    public void aRequiredDigestOfARequestWithABodyIsMade() throws Exception {
        RecordedRequest recorded = deliver(factory().setBodyDigestConfig(ApproovDefaultMessageSigning.DIGEST_SHA256, true),
                post("body".getBytes("UTF-8")));
        assertEquals("sha-256=:" + digest("SHA-256", "body") + ":", recorded.getHeader("Content-Digest"));
    }

    @Test
    public void anUnsupportedDigestAlgorithmIsRefusedWhenConfigured() {
        assertThrows(IllegalArgumentException.class, () -> factory().setBodyDigestConfig("md5", false));
    }
}
