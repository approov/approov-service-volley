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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The signed URL on the wire: for a URL that Android sends in another form than the app wrote it, the request
 * line the server receives is the path and query of the signed {@code @target-uri}, and the install signature
 * verifies over the signature base rebuilt from what the server received.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class WireUrlSigning370Test {
    private MiniSdkHttpsOrigins origins;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost", "127.0.0.1");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    // the target of the request line the server received
    private static String requestLineTarget(RecordedRequest recorded) {
        String[] parts = recorded.getRequestLine().split(" ");
        assertEquals(recorded.getRequestLine(), 3, parts.length);
        return parts[1];
    }

    /**
     * Rebuilds the install signature base from the request the server received and checks the install
     * signature over it with the public key of the installation.
     *
     * @param origin is the scheme and authority the request was sent to
     * @param recorded is the request the server received
     * @return the rebuilt signature base
     */
    static String verifyInstallSignature(String origin, RecordedRequest recorded) throws Exception {
        String input = recorded.getHeader("Signature-Input");
        String signature = recorded.getHeader("Signature");
        assertNotNull("signed", signature);
        Matcher member = Pattern.compile("install=(\\(([^)]*)\\)[^,]*)").matcher(input);
        assertTrue(input, member.find());
        StringBuilder base = new StringBuilder();
        Matcher component = Pattern.compile("\"([^\"]+)\"").matcher(member.group(2));
        List<String> components = new ArrayList<>();
        while (component.find())
            components.add(component.group(1));
        for (String name : components) {
            String value;
            if (name.equals("@method"))
                value = recorded.getMethod();
            else if (name.equals("@target-uri"))
                value = origin + requestLineTarget(recorded);
            else if (name.startsWith("@"))
                throw new AssertionError("component not rebuilt by the test: " + name);
            else
                value = recorded.getHeader(name).trim();
            base.append('"').append(name).append("\": ").append(value).append('\n');
        }
        base.append("\"@signature-params\": ").append(member.group(1));

        Matcher value = Pattern.compile("install=:([^:]*):").matcher(signature);
        assertTrue(signature, value.find());
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(Approov.getInstallPublicKey())));
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(key);
        verifier.update(base.toString().getBytes(StandardCharsets.UTF_8));
        assertTrue("the install signature verifies over\n" + base, verifier.verify(
                Base64.getDecoder().decode(value.group(1))));
        return base.toString();
    }

    @Test
    public void theRequestLineIsTheSignedTargetUriAndTheSignatureVerifies() throws Exception {
        String origin = "https://localhost:" + origins.first.getPort();
        String[][] cases = {
                {"/pipe|path?q=a|b", "/pipe%7Cpath?q=a|b"},
                {"/café?q=über✓", "/caf%C3%A9?q=%C3%BCber%E2%9C%93"},
                {"/a b?c d", "/a%20b?c%20d"},
                {"/pc%25t?q=100%25", "/pc%25t?q=100%25"},
        };
        for (String[] pair : cases) {
            origins.first.enqueue(MiniSdkHttpsOrigins.ok());
            // the URL is written by hand, as the server's own URL builder would already encode it
            origins.send(new MiniSdkHttpsOrigins.AppRequest(origin + pair[0] + "#fragment"));
            RecordedRequest recorded = origins.take(origins.first);
            assertNotNull(pair[0], recorded);
            assertEquals(pair[0], pair[1], requestLineTarget(recorded));
            assertTrue(recorded.getHeader("Signature-Input"),
                    recorded.getHeader("Signature-Input").contains("\"@target-uri\""));
            String base = verifyInstallSignature(origin, recorded);
            assertTrue(base, base.contains("\"@target-uri\": " + origin + pair[1] + "\n"));
        }
    }
}
