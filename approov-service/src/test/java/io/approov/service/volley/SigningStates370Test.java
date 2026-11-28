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

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The signing states on the wire. Out of the box no request is signed. With the default factory installed a
 * request carries the install signature only, and with the install and account opt-in both, over the same
 * components. A factory set for one host applies to that host only, and initialize turns signing off again.
 * The combined signer is the same two states with its own fetch decisions.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningStates370Test {
    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost", "127.0.0.1");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private RecordedRequest sendFirst() throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/data")));
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull(recorded);
        return recorded;
    }

    private static void assertUnsigned(String what, RecordedRequest recorded) {
        assertNull(what, recorded.getHeader("Signature"));
        assertNull(what, recorded.getHeader("Signature-Input"));
        assertNotNull(what + ": the token is still sent", recorded.getHeader("Approov-Token"));
    }

    private static void assertInstallOnly(String what, RecordedRequest recorded) {
        assertTrue(what, recorded.getHeader("Signature").startsWith("install=:"));
        assertFalse(what, recorded.getHeader("Signature").contains("account="));
        assertFalse(what, recorded.getHeader("Signature-Input").contains("account="));
        assertTrue(what, recorded.getHeader("Signature-Input").contains("\"approov-token\""));
    }

    private static void assertBoth(String what, RecordedRequest recorded) {
        assertTrue(what, recorded.getHeader("Signature").startsWith("install=:"));
        assertTrue(what, recorded.getHeader("Signature").contains("account=:"));
        assertTrue(what, recorded.getHeader("Signature-Input").contains("install=("));
        assertTrue(what, recorded.getHeader("Signature-Input").contains("account=("));
    }

    @Test
    public void signingIsOffInstallOnlyThenBoth() throws Exception {
        assertUnsigned("out of the box", sendFirst());

        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        assertInstallOnly("default factory", sendFirst());

        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning()));
        assertBoth("opt-in", sendFirst());
    }

    @Test
    public void aHostFactoryAppliesToItsHostOnly() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().putHostFactory("127.0.0.1",
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        assertUnsigned("another host", sendFirst());
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.secondUrl("/data")));
        assertInstallOnly("its own host", origins.take(origins.second));
    }

    @Test
    public void initializeTurnsSigningOff() throws Exception {
        ApproovService.setServiceMutator(new ApproovDefaultMessageSigning().setDefaultFactory(
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()));
        assertInstallOnly("before", sendFirst());
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost", "127.0.0.1");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        assertUnsigned("after initialize", sendFirst());
    }

    @Test
    public void theCombinedSignerSignsWithBothAndMakesTheDecisionsGiven() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        assertBoth("combined()", sendFirst());
        // the no-argument signer makes the standard decisions, which abort a network failure
        sdk.answerTokens(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-x");
        int before = origins.first.getRequestCount();
        try {
            origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/data")));
            org.junit.Assert.fail("a network failure must abort");
        } catch (ApproovNetworkException expected) {
            assertEquals(before, origins.first.getRequestCount());
        }

        // with the decisions of alwaysProceedMutator the failure goes out, signed
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        RecordedRequest recorded = sendFirst();
        assertEquals("", recorded.getHeader("Approov-Token"));
        assertBoth("combined(alwaysProceed)", recorded);
    }
}
