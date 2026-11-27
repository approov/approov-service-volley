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

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * WebSockets are not supported. A request carrying "Upgrade: websocket" is sent untouched: no token or secure
 * string fetch, no service mutator call, no token or trace header, no substitution and no signature. The value is
 * compared without regard to case. The JVM's HttpURLConnection does not send the Upgrade header itself, so the
 * server sees an ordinary request without anything Approov adds.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class WebSocketUpgrade370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;
    private final List<String> hooks = Collections.synchronizedList(new ArrayList<String>());

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, "secret"));
        ApproovService.addSubstitutionHeader("X-Secret", null);
        ApproovService.addSubstitutionQueryParam("key");
        // message signing whose decisions record every request hook they are asked
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders)
                    throws ApproovException {
                hooks.add("handleRequestShouldProcess");
                return ApproovServiceMutator.super.handleRequestShouldProcess(request, additionalHeaders);
            }
        }));
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private RecordedRequest send(String upgrade) throws Exception {
        MiniSdkHttpsOrigins.AppRequest request = new MiniSdkHttpsOrigins.AppRequest(
                origins.firstUrl("/socket") + "?key=" + PLACEHOLDER).header("X-Secret", PLACEHOLDER);
        if (upgrade != null)
            request.header("upgrade", upgrade).header("Connection", "Upgrade");
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    @Test
    public void aWebSocketUpgradeIsSentUntouched() throws Exception {
        for (String upgrade : new String[] {"websocket", "WebSocket"}) {
            RecordedRequest recorded = send(upgrade);
            MiniSdkHttpsOrigins.assertNoApproovHeaders(upgrade, recorded);
            assertEquals(upgrade, PLACEHOLDER, recorded.getHeader("X-Secret"));
            assertEquals(upgrade, PLACEHOLDER, recorded.getRequestUrl().queryParameter("key"));
        }
        assertEquals("no token fetch", 0, sdk.count("fetchApproovTokenAndWait"));
        assertEquals("no secure string fetch", 0, sdk.count("fetchSecureStringAndWait"));
        assertEquals("no mutator hook", Collections.emptyList(), hooks);
    }

    @Test
    public void control_anOrdinaryRequestIsProtected() throws Exception {
        RecordedRequest recorded = send(null);
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("secret", recorded.getHeader("X-Secret"));
        assertNotNull(recorded.getHeader("Signature"));
        assertTrue(hooks.contains("handleRequestShouldProcess"));
    }
}
