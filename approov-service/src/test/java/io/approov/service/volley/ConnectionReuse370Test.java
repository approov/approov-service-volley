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
import static org.junit.Assert.fail;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * The pins are checked by the hostname verifier, which runs only in the TLS handshake of a new connection. Every
 * https connection the layer opens while Approov protection is enabled asks the server to close it after the
 * response, pinned or not, so that each request starts with a handshake its own verifier checks: a pinned
 * request never reuses a connection that was not pinned, and a pin change applies to the next request. The
 * fixture servers close the connection when asked, as an HTTP/1.1 server must.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ConnectionReuse370Test {
    private static final String WRONG_PIN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    // true while the pinning hook opts every request out
    private volatile boolean optOut;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true, false);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handlePinningShouldProcessRequest(Request<?> request) {
                return !optOut;
            }
        });
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private void pins(String pin) {
        Map<String, List<String>> pins = Collections.singletonMap("localhost", Collections.singletonList(pin));
        sdk.pins = pins;
    }

    private RecordedRequest deliver(MiniSdkHttpsOrigins.AppRequest request) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(request).getStatusCode());
        return origins.take(origins.first);
    }

    private void assertRefused(String what) throws Exception {
        int before = origins.first.getRequestCount();
        try {
            origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/refused")));
            fail(what + ": a host whose certificate fails the pin was reached");
        } catch (SSLPeerUnverifiedException e) {
            assertEquals("Approov pinning: no pin matches for localhost", e.getMessage());
        }
        assertEquals(what + ": nothing reached the server", before, origins.first.getRequestCount());
    }

    @Test
    public void everyConnectionAsksTheServerToClose() throws Exception {
        pins(origins.serverPin());
        assertEquals("pinned", "close", deliver(new MiniSdkHttpsOrigins.AppRequest(
                origins.firstUrl("/pinned"))).getHeader("Connection"));
        optOut = true;
        assertEquals("opted out", "close", deliver(new MiniSdkHttpsOrigins.AppRequest(
                origins.firstUrl("/opted-out"))).getHeader("Connection"));
        assertEquals("WebSocket upgrade", "close", deliver(new MiniSdkHttpsOrigins.AppRequest(
                origins.firstUrl("/socket")).header("Upgrade", "websocket")).getHeader("Connection"));
    }

    @Test
    public void eachRequestIsSentOnANewConnection() throws Exception {
        pins(origins.serverPin());
        for (int i = 0; i < 3; i++) {
            RecordedRequest recorded = deliver(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/" + i)));
            assertEquals("request " + i + " reused a connection", 0, recorded.getSequenceNumber());
        }
    }

    @Test
    public void aPinnedRequestAfterAnOptedOutOneIsChecked() throws Exception {
        pins(WRONG_PIN);
        optOut = true;
        deliver(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/opted-out")));
        optOut = false;
        assertRefused("after an opted out request");
    }

    @Test
    public void aPinnedRequestAfterAWebSocketUpgradeIsChecked() throws Exception {
        pins(WRONG_PIN);
        deliver(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/socket")).header("Upgrade", "websocket"));
        assertRefused("after a WebSocket upgrade");
    }

    @Test
    public void aPinChangeAppliesToTheNextRequest() throws Exception {
        pins(origins.serverPin());
        deliver(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/before")));
        pins(WRONG_PIN);
        assertRefused("after a pin change");
        pins(origins.serverPin());
        deliver(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/after")));
    }

    @Test
    public void aRedirectHopIsSentOnANewConnection() throws Exception {
        pins(origins.serverPin());
        origins.first.enqueue(new MockResponse().setResponseCode(302)
                .setHeader("Location", origins.firstUrl("/landing")).setBody("moved"));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/start")))
                .getStatusCode());
        origins.take(origins.first);
        RecordedRequest hop = origins.take(origins.first);
        assertEquals("/landing", hop.getPath());
        assertEquals("the hop asks the server to close", "close", hop.getHeader("Connection"));
        assertEquals("the hop reused a connection", 0, hop.getSequenceNumber());
    }
}
