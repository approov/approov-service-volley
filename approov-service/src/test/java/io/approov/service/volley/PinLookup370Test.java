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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.util.Log;

import com.android.volley.NoConnectionError;
import com.android.volley.VolleyError;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Pin lookup and the pin decisions of PinningHostnameVerifier, as the OkHttp service layer makes them. The pins
 * of a connection are looked up exactly per host, without regard to case and ignoring one trailing dot, on both the
 * host and the keys of the SDK pin set. The "*" key is the managed trust roots of a listed host with no pins of
 * its own, never a pattern. A listed host with no pins and no managed trust roots connects on OS trust with one
 * warning per host. A pin set that cannot be read fails the connection closed, and a pin mismatch fails it, both
 * with SSLPeerUnverifiedException, logged at error level without any pin.
 * <p>
 * The verifier is called directly with the certificate the fixture servers present, and on the wire through the
 * Volley stack with a certificate that does not name the host, so that the JVM asks the verifier.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class PinLookup370Test {
    // a pin no fixture certificate matches
    private static final String WRONG_PIN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private static final String OS_TRUST_WARNING =
            "Approov domain localhost: no pins and no managed trust roots, OS trust only";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;
    private String rightPin;
    private SSLSession session;

    @Before
    public void setUp() throws Exception {
        ShadowLog.reset();
        origins = new MiniSdkHttpsOrigins(true, false);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        rightPin = origins.serverPin();
        session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[] {origins.certificate.certificate()});
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
        ShadowLog.reset();
    }

    // the pin set the SDK reports, from alternating keys and pin lists
    private void pins(Object... keysAndPins) {
        Map<String, List<String>> map = new HashMap<>();
        for (int i = 0; i < keysAndPins.length; i += 2) {
            @SuppressWarnings("unchecked")
            List<String> list = (List<String>) keysAndPins[i + 1];
            map.put((String) keysAndPins[i], list);
        }
        sdk.pins = map;
    }

    private static List<String> list(String... pins) {
        return new ArrayList<>(Arrays.asList(pins));
    }

    private PinningHostnameVerifier verifier() {
        return new PinningHostnameVerifier((hostname, sslSession) -> true);
    }

    private boolean verify(String host) {
        return verifier().verify(host, session);
    }

    // the lines the pin verifier logged at the given level
    private static List<String> logged(int type) {
        List<String> lines = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ("ApproovPinVerifier".equals(item.tag) && (item.type == type))
                lines.add(item.msg);
        }
        return lines;
    }

    private void assertNoPinIn(String what, String text) {
        assertFalse(what + " names a pin: " + text, text.contains(WRONG_PIN) || text.contains(rightPin));
    }

    @Test
    public void aKeyMatchesWithoutRegardToCase() {
        pins("LocalHost", list(WRONG_PIN));
        assertFalse("a key LocalHost pins localhost", verify("localhost"));
        pins("LOCALHOST", list(rightPin));
        assertTrue(verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertFalse("a key localhost pins LocalHost", verify("LocalHost"));
    }

    @Test
    public void oneTrailingDotIsIgnoredOnTheKeyAndTheHost() {
        pins("localhost.", list(WRONG_PIN));
        assertFalse("a key localhost. pins localhost", verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertFalse("localhost. is checked against the pins of localhost", verify("localhost."));
        pins("localhost.", list(rightPin));
        assertTrue(verify("LOCALHOST."));
    }

    @Test
    public void theManagedTrustRootsApplyToAListedHostUnderAnySpelling() {
        pins("LocalHost.", list(), "*", list(WRONG_PIN));
        assertFalse(verify("localhost"));
        assertFalse(verify("localhost."));
        pins("LocalHost.", list(), "*", list(rightPin));
        assertTrue(verify("localhost"));
        // a host with pins of its own does not use them
        pins("localhost", list(WRONG_PIN), "*", list(rightPin));
        assertFalse(verify("localhost"));
    }

    @Test
    public void aKeyIsNeverAPattern() {
        // the managed trust roots never apply to a host that is not listed
        pins("*", list(WRONG_PIN));
        assertTrue("* is not a wildcard", verify("localhost"));
        // the pins of a domain never apply to its subdomains or a host that contains it
        pins("host", list(WRONG_PIN), "calhost", list(WRONG_PIN), "*.localhost", list(WRONG_PIN));
        assertTrue(verify("localhost"));
        pins("localhost", list(WRONG_PIN));
        assertTrue("a subdomain is not pinned by its parent", verify("api.localhost"));
        assertEquals("no warning for a host that is not listed", Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void anEmptyPinSetListsNoHost() {
        pins();
        assertTrue(verify("localhost"));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void aListedHostWithNoPinsAndNoManagedTrustRootsWarnsOncePerHost() {
        // no "*" key
        pins("localhost", list());
        assertTrue(verify("localhost"));
        assertTrue(verify("LocalHost"));
        assertTrue(verify("localhost."));
        assertEquals(Collections.singletonList(OS_TRUST_WARNING), logged(Log.WARN));

        // an empty "*", for another host
        pins("LOCALHOST.", list(), "127.0.0.1", list(), "*", list());
        assertTrue(verify("127.0.0.1"));
        assertTrue(verify("127.0.0.1"));
        assertTrue(verify("localhost"));
        assertEquals(Arrays.asList(OS_TRUST_WARNING,
                "Approov domain 127.0.0.1: no pins and no managed trust roots, OS trust only"), logged(Log.WARN));
    }

    @Test
    public void noWarningForValidManagedTrustRootsOrAHostWithPins() {
        pins("localhost", list(), "*", list(rightPin));
        assertTrue(verify("localhost"));
        pins("localhost", list(rightPin));
        assertTrue(verify("localhost"));
        // a host with pins under another spelling is never OS trust only
        pins("localhost", list(), "LOCALHOST", list(rightPin));
        assertTrue(verify("localhost"));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
    }

    @Test
    public void aMismatchIsLoggedAtErrorWithoutAnyPin() {
        pins("localhost", list(WRONG_PIN, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
        PinningHostnameVerifier verifier = verifier();
        assertFalse(verifier.verify("LocalHost", session));
        assertEquals(Collections.singletonList("Approov pinning: no pin matches for localhost"), logged(Log.ERROR));
        assertEquals(Collections.emptyList(), logged(Log.WARN));
        SSLPeerUnverifiedException failure = verifier.failure();
        assertNotNull(failure);
        assertEquals("Approov pinning: no pin matches for localhost", failure.getMessage());
    }

    @Test
    public void aMatchRecordsNoFailure() {
        pins("localhost", list(WRONG_PIN, rightPin));
        PinningHostnameVerifier verifier = verifier();
        assertTrue(verifier.verify("localhost", session));
        assertNull(verifier.failure());
        assertEquals(Collections.emptyList(), logged(Log.ERROR));
    }

    @Test
    public void aNullPinSetFailsClosed() {
        sdk.pinsAnswer = () -> null;
        PinningHostnameVerifier verifier = verifier();
        assertFalse("a pin set that cannot be read must not pass", verifier.verify("localhost", session));
        SSLPeerUnverifiedException failure = verifier.failure();
        assertNotNull(failure);
        assertEquals("Approov pinning: pins unavailable for localhost", failure.getMessage());
        assertEquals(1, logged(Log.ERROR).size());
        assertTrue(logged(Log.ERROR).get(0), logged(Log.ERROR).get(0)
                .startsWith("Approov pinning: pins unavailable for localhost: "));
    }

    @Test
    public void aPinSetTheSdkFailsToGiveFailsClosed() {
        IllegalStateException sdkFailure = new IllegalStateException("sdk failure");
        sdk.pinsAnswer = () -> {
            throw sdkFailure;
        };
        PinningHostnameVerifier verifier = verifier();
        assertFalse(verifier.verify("localhost", session));
        assertEquals("Approov pinning: pins unavailable for localhost", verifier.failure().getMessage());
        assertSame(sdkFailure, verifier.failure().getCause());
        assertEquals(Collections.singletonList("Approov pinning: pins unavailable for localhost: " + sdkFailure),
                logged(Log.ERROR));
    }

    @Test
    public void aDomainWithNoPinListFailsClosed() {
        pins("localhost", null);
        PinningHostnameVerifier verifier = verifier();
        assertFalse(verifier.verify("localhost", session));
        assertEquals("Approov pinning: pins unavailable for localhost", verifier.failure().getMessage());
    }

    @Test
    public void aMismatchOnTheWireFailsWithThePlatformPinningException() throws Exception {
        pins("localhost", list(WRONG_PIN));
        try {
            origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/pinned")));
            fail("a mispinned host was reached");
        } catch (SSLPeerUnverifiedException e) {
            assertEquals("Approov pinning: no pin matches for localhost", e.getMessage());
            assertNoPinIn("the exception", e.toString());
        }
        assertEquals("nothing reached the server", 0, origins.first.getRequestCount());

        // as Volley delivers it to the app
        VolleyError error = origins.perform(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/pinned")));
        assertTrue(String.valueOf(error), error instanceof NoConnectionError);
        assertTrue(String.valueOf(error.getCause()), error.getCause() instanceof SSLPeerUnverifiedException);
        for (String line : logged(Log.ERROR))
            assertNoPinIn("the log", line);
    }

    @Test
    public void unreadablePinsOnTheWireFailWithThePlatformPinningException() throws Exception {
        sdk.pinsAnswer = () -> {
            throw new IllegalStateException("sdk failure");
        };
        try {
            origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/pinned")));
            fail("a host was reached with no pins read");
        } catch (SSLPeerUnverifiedException e) {
            assertEquals("Approov pinning: pins unavailable for localhost", e.getMessage());
        }
        assertEquals(0, origins.first.getRequestCount());
    }

    @Test
    public void aListedHostWithNoPinsConnectsOnOsTrustOnTheWire() throws Exception {
        pins("localhost", list(), "127.0.0.1", list(WRONG_PIN));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/a"))).getStatusCode());
        assertEquals(200, origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/b"))).getStatusCode());
        assertEquals(Collections.singletonList(OS_TRUST_WARNING), logged(Log.WARN));
    }

    @Test
    public void aHostNotListedConnectsOnOsTrustOnTheWire() throws Exception {
        sdk.tokenAnswer = url -> MiniSdkHook.result(Approov.TokenFetchStatus.UNKNOWN_URL, null, null, null);
        pins("localhost", list(WRONG_PIN), "*", list(WRONG_PIN));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.secondUrl("/a")))
                .getStatusCode());
        assertEquals(Collections.emptyList(), logged(Log.WARN));
    }
}
