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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.volley.Request;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.HttpResponse;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * The pinning hook, handlePinningShouldProcessRequest, is asked for every request the layer sends while Approov
 * protection is enabled and again for each redirect hop the layer follows, with the attempt as it is sent, and
 * under the mutator the request was first processed with. A request or hop it opts out gets no Approov pinning
 * and relies on OS trust only. A runtime exception from it fails the request as a hook failure naming the hook.
 * The standard mutators pin every request, and message signing forwards the hook to its decisions.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class PinningHook370Test {
    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    // the URLs the pinning hook was asked about, in order
    private final List<String> asked = Collections.synchronizedList(new ArrayList<String>());

    // the connections the stack created, in order
    private final List<HttpURLConnection> connections = Collections.synchronizedList(
            new ArrayList<HttpURLConnection>());

    // a stack that records the connections it creates
    private final ApproovHurlStack stack = new ApproovHurlStack() {
        @Override
        protected HttpURLConnection createConnection(URL url) throws IOException {
            HttpURLConnection connection = super.createConnection(url);
            connections.add(connection);
            return connection;
        }
    };

    private void start(boolean namesHosts) throws Exception {
        origins = new MiniSdkHttpsOrigins(true, namesHosts);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        sdk.tokenAnswer = url -> url.contains("//localhost:")
                ? MiniSdkHook.result(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1", null)
                : MiniSdkHook.result(Approov.TokenFetchStatus.UNKNOWN_URL, null, null, null);
    }

    @After
    public void tearDown() throws Exception {
        if (origins != null)
            origins.shutdown();
    }

    // a mutator whose pinning hook records the URL it is asked about and answers with the decision given
    private ApproovServiceMutator pinningDecidedBy(PinDecision decision) {
        return new ApproovServiceMutator() {
            @Override
            public boolean handlePinningShouldProcessRequest(Request<?> request) {
                asked.add(request.getUrl());
                return decision.pin(request.getUrl());
            }
        };
    }

    interface PinDecision {
        boolean pin(String url);
    }

    // sends a request through the recording stack and reads its body
    private HttpResponse send(String url) throws Exception {
        HttpResponse response = stack.executeRequest(new MiniSdkHttpsOrigins.AppRequest(url),
                Collections.<String, String>emptyMap());
        InputStream content = response.getContent();
        if (content != null)
            content.close();
        return response;
    }

    // true if the connection is checked against the Approov pins
    private static boolean pinned(HttpURLConnection connection) {
        return (connection instanceof HttpsURLConnection)
                && (((HttpsURLConnection) connection).getHostnameVerifier() instanceof PinningHostnameVerifier);
    }

    private static MockResponse redirect(String location) {
        return new MockResponse().setResponseCode(302).setHeader("Location", location).setBody("moved");
    }

    @Test
    public void theStandardMutatorsPinEveryRequest() throws Exception {
        Request<?> request = ApproovTestSupport.request("https://api.example.com/");
        Map<String, ApproovServiceMutator> standard = new HashMap<>();
        standard.put("CLOSE_FAILURE", ApproovServiceMutator.CLOSE_FAILURE);
        standard.put("ALWAYS_PROCEED", ApproovServiceMutator.ALWAYS_PROCEED);
        standard.put("DEFAULT", ApproovServiceMutator.DEFAULT);
        standard.put("interface default", new ApproovServiceMutator() {
        });
        standard.put("message signing", new ApproovDefaultMessageSigning());
        standard.put("combined()", ApproovDefaultMessageSigning.combined());
        standard.put("combined(ALWAYS_PROCEED)",
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        for (Map.Entry<String, ApproovServiceMutator> entry : standard.entrySet())
            assertTrue(entry.getKey(), entry.getValue().handlePinningShouldProcessRequest(request));
    }

    @Test
    public void messageSigningForwardsTheHookToItsDecisions() throws Exception {
        Request<?> request = ApproovTestSupport.request("https://api.example.com/");
        assertFalse(ApproovDefaultMessageSigning.combined(pinningDecidedBy(url -> false))
                .handlePinningShouldProcessRequest(request));
        assertEquals(Collections.singletonList("https://api.example.com/"), asked);
    }

    @Test
    public void theHookIsAskedForTheRequestAndEachRedirectHop() throws Exception {
        start(true);
        ApproovService.setServiceMutator(pinningDecidedBy(url -> true));
        origins.first.enqueue(redirect(origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, send(origins.firstUrl("/start")).getStatusCode());
        assertEquals(Arrays.asList(origins.firstUrl("/start"), origins.secondUrl("/landing")), asked);
        assertEquals(2, connections.size());
        assertTrue("the request is pinned", pinned(connections.get(0)));
        assertTrue("the hop is pinned", pinned(connections.get(1)));
    }

    @Test
    public void anOptedOutRequestOrHopGetsNoApproovPinning() throws Exception {
        start(true);
        // the request is pinned and its hop opted out
        ApproovService.setServiceMutator(pinningDecidedBy(url -> url.contains("//localhost:")));
        origins.first.enqueue(redirect(origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        send(origins.firstUrl("/start"));
        assertTrue("the request is pinned", pinned(connections.get(0)));
        assertFalse("the opted out hop is not pinned", pinned(connections.get(1)));

        // the request opted out and its hop pinned
        connections.clear();
        ApproovService.setServiceMutator(pinningDecidedBy(url -> !url.contains("//localhost:")));
        origins.first.enqueue(redirect(origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        send(origins.firstUrl("/start"));
        assertFalse("the opted out request is not pinned", pinned(connections.get(0)));
        assertTrue("the hop is pinned", pinned(connections.get(1)));
    }

    @Test
    public void anExcludedRequestIsStillAskedAndPinned() throws Exception {
        start(true);
        ApproovService.setServiceMutator(pinningDecidedBy(url -> true));
        ApproovService.addExclusionURLRegex(".*/excluded.*");
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        send(origins.firstUrl("/excluded"));
        MiniSdkHttpsOrigins.assertNoApproovHeaders("excluded", origins.take(origins.first));
        assertEquals(Collections.singletonList(origins.firstUrl("/excluded")), asked);
        assertTrue("an excluded request to a protected host is still pinned", pinned(connections.get(0)));
    }

    @Test
    public void aMispinnedHostIsRefusedUnlessTheHookOptsOut() throws Exception {
        start(false);
        Map<String, List<String>> pins = new HashMap<>();
        pins.put("localhost", Collections.singletonList("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        sdk.pins = pins;

        // pinned, the connection is refused before anything is sent
        ApproovService.setServiceMutator(pinningDecidedBy(url -> true));
        try {
            send(origins.firstUrl("/pinned"));
            fail("a mispinned host was reached");
        } catch (IOException e) {
            // refused by the pin
        }
        assertEquals("nothing reached the server", 0, origins.first.getRequestCount());

        // opted out, the same host is reached on OS trust only
        ApproovService.setServiceMutator(pinningDecidedBy(url -> false));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, send(origins.firstUrl("/opted-out")).getStatusCode());
        assertEquals("jwt-token", origins.take(origins.first).getHeader("Approov-Token"));
    }

    @Test
    public void control_aCorrectlyPinnedHostIsReached() throws Exception {
        start(false);
        sdk.pins = Collections.singletonMap("localhost", Collections.singletonList(origins.serverPin()));
        ApproovService.setServiceMutator(pinningDecidedBy(url -> true));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, send(origins.firstUrl("/pinned")).getStatusCode());
    }

    @Test
    public void aRuntimeExceptionFromTheHookIsAHookFailure() throws Exception {
        start(true);
        IllegalStateException appAbort = new IllegalStateException("app abort");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handlePinningShouldProcessRequest(Request<?> request) {
                throw appAbort;
            }
        });
        VolleyError error = origins.perform(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/abort")));
        assertNotNull("the request was not aborted", error);
        assertTrue(error.toString(), error instanceof ApproovException);
        assertEquals("ApproovServiceMutator.handlePinningShouldProcessRequest failed: " + appAbort,
                error.getMessage());
        assertSame(appAbort, error.getCause());
        assertEquals("nothing was sent", 0, origins.first.getRequestCount());
    }

    @Test
    public void theHookIsAskedUnderTheMutatorTheRequestStartedWith() throws Exception {
        start(true);
        ApproovServiceMutator later = pinningDecidedBy(url -> {
            throw new AssertionError("the hop was decided by a mutator installed after the request started");
        });
        ApproovService.setServiceMutator(pinningDecidedBy(url -> true));
        origins.first.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                // a mutator installed while the request is in flight
                ApproovService.setServiceMutator(later);
                return redirect(origins.secondUrl("/landing"));
            }
        });
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, send(origins.firstUrl("/start")).getStatusCode());
        assertEquals(Arrays.asList(origins.firstUrl("/start"), origins.secondUrl("/landing")), asked);
    }
}
