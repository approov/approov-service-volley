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

import android.util.Log;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * When the layer does not deliver a secure string (any secure string status other than SUCCESS, or a channel
 * that allows no secrets) or lets a request proceed on a token fetch failure, it logs at DEBUG only: the
 * header or query parameter name (never a value, placeholder or secret), the fetch status, and the ARC and
 * rejection reasons when the SDK gives them. At the default INFO level none of this is logged, at any
 * severity. A placeholder left because the request is not https is a configuration problem and stays a
 * warning.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class UndeliveredDiagnostics370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";
    private static final String ARC = "ARCDIAG1";
    private static final String REASONS = "rooted-device";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        ApproovService.addSubstitutionHeader("Api-Key", null);
        ApproovService.addSubstitutionQueryParam("key");
        ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private MiniSdkHttpsOrigins.AppRequest request(String url) {
        return new MiniSdkHttpsOrigins.AppRequest(url + "?key=" + PLACEHOLDER).header("Api-Key", PLACEHOLDER);
    }

    // answers the token fetch with the given status, and the secure string fetch with the status given
    private void answer(Approov.TokenFetchStatus token, Approov.TokenFetchStatus secureString) {
        sdk.tokenAnswer = url -> MiniSdkHook.result(token,
                (token == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token" : null, "trace-1", null, ARC, REASONS);
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.result(secureString, null, null,
                (secureString == Approov.TokenFetchStatus.SUCCESS) ? SECRET : null, ARC, REASONS));
    }

    // sends a request to the first origin, clearing the log just before
    private RecordedRequest sendFirst() throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        ShadowLog.reset();
        origins.send(request(origins.firstUrl("/data")));
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    // every line logged since the last send that carries the diagnostic ARC, after checking that no line holds
    // a placeholder or a secret
    private static List<ShadowLog.LogItem> diagnostics() {
        List<ShadowLog.LogItem> lines = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            assertFalse("a value was logged: " + item.msg, item.msg.contains(PLACEHOLDER));
            assertFalse("a secret was logged: " + item.msg, item.msg.contains(SECRET));
            if (item.msg.contains(ARC))
                lines.add(item);
        }
        return lines;
    }

    private static void assertDebugLine(List<ShadowLog.LogItem> lines, String... parts) {
        for (ShadowLog.LogItem item : lines) {
            boolean all = true;
            for (String part : parts)
                all &= item.msg.contains(part);
            if (all) {
                assertEquals("logged above DEBUG: " + item.msg, Log.DEBUG, item.type);
                return;
            }
        }
        throw new AssertionError("no DEBUG line with " + Arrays.toString(parts) + " in " + messages(lines));
    }

    private static List<String> messages(List<ShadowLog.LogItem> lines) {
        List<String> out = new ArrayList<>();
        for (ShadowLog.LogItem item : lines)
            out.add(item.msg);
        return out;
    }

    private static void assertAllDebug(List<ShadowLog.LogItem> lines) {
        for (ShadowLog.LogItem item : lines)
            assertEquals(item.msg, Log.DEBUG, item.type);
    }

    @Test
    public void aTokenFailureIsLoggedAtDebugWithItsArcAndReasons() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        answer(Approov.TokenFetchStatus.REJECTED, Approov.TokenFetchStatus.SUCCESS);
        RecordedRequest recorded = sendFirst();
        // the placeholders stay, and the secret is not on the wire
        assertEquals(PLACEHOLDER, recorded.getHeader("Api-Key"));
        List<ShadowLog.LogItem> lines = diagnostics();
        // the request proceeding on the failure
        assertDebugLine(lines, "Approov token fetch for localhost: REJECTED", ARC, REASONS,
                "proceeding with an empty token header");
        // the secure strings the failure channel does not deliver, by name
        assertDebugLine(lines, "header Api-Key", "token fetch status REJECTED", ARC, REASONS);
        assertDebugLine(lines, "query parameter key", "token fetch status REJECTED", ARC, REASONS);
        assertAllDebug(lines);

        // with the status used in the token header the line says so
        ApproovService.setUseApproovStatusIfNoToken(true);
        sendFirst();
        assertDebugLine(diagnostics(), "Approov token fetch for localhost: REJECTED", ARC, REASONS,
                "proceeding with the status in the token header");
    }

    @Test
    public void aSecureStringFailureIsLoggedAtDebugWithItsArcAndReasons() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        answer(Approov.TokenFetchStatus.SUCCESS, Approov.TokenFetchStatus.REJECTED);
        RecordedRequest recorded = sendFirst();
        assertEquals("the status is sent in place of the secure string", "REJECTED", recorded.getHeader("Api-Key"));
        List<ShadowLog.LogItem> lines = diagnostics();
        assertDebugLine(lines, "header Api-Key", "secure string fetch status REJECTED", ARC, REASONS,
                "status sent in its place");
        assertDebugLine(lines, "query parameter key", "secure string fetch status REJECTED", ARC, REASONS,
                "status sent in its place");
        assertAllDebug(lines);
    }

    @Test
    public void aFailureToAHostNotInThePinSetIsLoggedAtDebug() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        sdk.listHosts("localhost");
        sdk.tokenAnswer = url -> MiniSdkHook.result(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "trace-1",
                null, ARC, "");
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        ShadowLog.reset();
        origins.send(request(origins.secondUrl("/data")));
        RecordedRequest recorded = origins.take(origins.second);
        assertNotNull(recorded);
        assertEquals(PLACEHOLDER, recorded.getHeader("Api-Key"));
        List<ShadowLog.LogItem> lines = diagnostics();
        assertDebugLine(lines, "Approov token fetch for 127.0.0.1: NO_APPROOV_SERVICE", ARC,
                "not an Approov API domain, proceeding untouched");
        assertDebugLine(lines, "header Api-Key", "token fetch status NO_APPROOV_SERVICE", ARC);
        assertDebugLine(lines, "query parameter key", "token fetch status NO_APPROOV_SERVICE", ARC);
    }

    @Test
    public void aTokenFailureSentWithNoApproovHeaderIsLoggedAtDebug() throws Exception {
        // a custom mutator that lets a failure proceed with no Approov header at all
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
                return approovResults.getStatus() == Approov.TokenFetchStatus.SUCCESS;
            }
        });
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        answer(Approov.TokenFetchStatus.REJECTED, Approov.TokenFetchStatus.SUCCESS);
        RecordedRequest recorded = sendFirst();
        MiniSdkHttpsOrigins.assertNoApproovHeaders("no header", recorded);
        assertDebugLine(diagnostics(), "Approov token fetch for localhost: REJECTED", ARC, REASONS,
                "proceeding with no Approov header");
    }

    @Test
    public void anAbortIgnoredForAHostNotInThePinSetIsLoggedAtDebug() throws Exception {
        // CLOSE_FAILURE throws for REJECTED, which is ignored for a host that is not an Approov API domain
        ApproovService.setServiceMutator(ApproovServiceMutator.CLOSE_FAILURE);
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        sdk.tokenAnswer = url -> MiniSdkHook.result(Approov.TokenFetchStatus.REJECTED, null, null, null, null, null);
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        ShadowLog.reset();
        origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.secondUrl("/data")));
        assertNotNull(origins.take(origins.second));
        boolean logged = false;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (item.msg.equals("handleRequestFetchTokenResult: abort ignored for 127.0.0.1, "
                    + "not an Approov API domain")) {
                assertEquals("logged above DEBUG: " + item.msg, Log.DEBUG, item.type);
                logged = true;
            }
        }
        assertTrue("no DEBUG line for the ignored abort", logged);
    }

    @Test
    public void nothingIsLoggedAtInfo() throws Exception {
        // INFO is the default level
        ApproovService.setLoggingLevel(ApproovLogLevel.INFO);
        answer(Approov.TokenFetchStatus.REJECTED, Approov.TokenFetchStatus.SUCCESS);
        sendFirst();
        assertTrue("logged at INFO: " + messages(diagnostics()), diagnostics().isEmpty());
        assertNoLineNaming("Api-Key");
        answer(Approov.TokenFetchStatus.SUCCESS, Approov.TokenFetchStatus.REJECTED);
        sendFirst();
        assertTrue("logged at INFO: " + messages(diagnostics()), diagnostics().isEmpty());
        assertNoLineNaming("Api-Key");
    }

    @Test
    public void aCleartextRequestIsStillAWarning() throws Exception {
        // a placeholder left because the request is not https (or its token fetch returned BAD_URL) is a
        // configuration problem and stays a warning, visible at the default level
        MiniSdkHttpsOrigins cleartext = new MiniSdkHttpsOrigins(false);
        try {
            MiniSdkHook hook = cleartext.initialize(new MiniSdkHook());
            hook.listHosts("localhost", "127.0.0.1");
            ApproovService.addSubstitutionHeader("Api-Key", null);
            ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
            hook.tokenAnswer = url -> MiniSdkHook.result(Approov.TokenFetchStatus.BAD_URL, null, null, null);
            cleartext.second.enqueue(MiniSdkHttpsOrigins.ok());
            ShadowLog.reset();
            cleartext.send(new MiniSdkHttpsOrigins.AppRequest(cleartext.secondUrl("/data"))
                    .header("Api-Key", PLACEHOLDER));
            assertNotNull(cleartext.take(cleartext.second));
            boolean warned = false;
            for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
                assertFalse("a value was logged: " + item.msg, item.msg.contains(PLACEHOLDER));
                warned |= (item.type == Log.WARN) && item.msg.contains("header Api-Key")
                        && item.msg.contains("request is not https");
            }
            assertTrue("no warning naming the header", warned);
        } finally {
            cleartext.shutdown();
        }
    }

    private static void assertNoLineNaming(String name) {
        for (ShadowLog.LogItem item : ShadowLog.getLogs())
            assertFalse("logged at INFO: " + item.msg, item.msg.contains(name));
    }
}
