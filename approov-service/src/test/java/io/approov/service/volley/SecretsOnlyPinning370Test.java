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
import static org.junit.Assert.fail;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * A secrets-only API (the SDK reports UNPROTECTED_URL) is pinned like any Approov API domain: a connection
 * to a host whose certificate matches none of its pins fails with the platform pinning exception before any
 * request is sent, under both standard decisions and with signing installed. With the right pin the secure
 * strings are substituted and the request carries no token, trace or signature header.
 * <p>
 * The certificate of the fixture names neither host, so that the JVM asks the layer's verifier.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SecretsOnlyPinning370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";
    private static final String WRONG_PIN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true, false);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.answerTokens(Approov.TokenFetchStatus.UNPROTECTED_URL, null, "trace-u");
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, SECRET));
        ApproovService.addSubstitutionHeader("Api-Key", null);
        ApproovService.addSubstitutionQueryParam("key");
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private void pin(String pin) {
        Map<String, List<String>> map = new HashMap<>();
        map.put("localhost", new ArrayList<>(Collections.singletonList(pin)));
        sdk.pins = map;
    }

    private MiniSdkHttpsOrigins.AppRequest request() {
        return new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/data") + "?key=" + PLACEHOLDER)
                .header("Api-Key", PLACEHOLDER);
    }

    private static ApproovServiceMutator[] signedDecisions() {
        return new ApproovServiceMutator[] {
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE),
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED),
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED};
    }

    @Test
    public void aWrongPinFailsTheConnectionBeforeAnythingIsSent() throws Exception {
        pin(WRONG_PIN);
        for (ApproovServiceMutator mutator : signedDecisions()) {
            ApproovService.setServiceMutator(mutator);
            try {
                origins.send(request());
                fail(mutator + ": a mispinned host was reached");
            } catch (SSLPeerUnverifiedException e) {
                assertEquals("Approov pinning: no pin matches for localhost", e.getMessage());
            }
            assertEquals(mutator + ": nothing reached the server", 0, origins.first.getRequestCount());
        }
    }

    @Test
    public void theRightPinSubstitutesAndSendsNoApproovHeader() throws Exception {
        pin(origins.serverPin());
        for (ApproovServiceMutator mutator : signedDecisions()) {
            ApproovService.setServiceMutator(mutator);
            origins.first.enqueue(MiniSdkHttpsOrigins.ok());
            origins.send(request());
            RecordedRequest recorded = origins.take(origins.first);
            assertNotNull(mutator.toString(), recorded);
            assertEquals(mutator + ": header", SECRET, recorded.getHeader("Api-Key"));
            assertEquals(mutator + ": query", SECRET, recorded.getRequestUrl().queryParameter("key"));
            MiniSdkHttpsOrigins.assertNoApproovHeaders(mutator.toString(), recorded);
        }
    }
}
