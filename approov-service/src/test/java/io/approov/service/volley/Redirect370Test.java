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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.volley.Request;
import com.android.volley.toolbox.HttpResponse;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * The layer follows redirects itself, as HttpURLConnection would (300 to 303 for any method, a method that permits
 * a body becoming GET without one; 307 and 308 for GET and HEAD only; never to another scheme; at most 20
 * follow-ups), and evaluates every hop as a new request for its own URL: the protection added for the previous
 * hop is stripped, the token is fetched for the target, the app's placeholders are substituted only if the
 * target is a protected channel, and the target is signed over its own URL and method. A redirect to another
 * origin carries nothing the layer added and no substituted value, while the app's own headers go on as the
 * platform sends them, without Authorization. The URL the server sent is followed as it is: its query is never
 * looked up as secure string keys and an echoed secret is never restored.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class Redirect370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        start(true);
    }

    private void start(boolean secondOverTls) throws Exception {
        origins = new MiniSdkHttpsOrigins(secondOverTls);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        // localhost is token-protected, and 127.0.0.1 is not added to Approov unless a test says otherwise
        tokensBy(Approov.TokenFetchStatus.UNKNOWN_URL);
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, SECRET));
        ApproovService.addSubstitutionHeader("X-Secret", null);
        ApproovService.addSubstitutionQueryParam("key");
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
    }

    @After
    public void tearDown() throws Exception {
        HttpURLConnection.setFollowRedirects(true);
        origins.shutdown();
    }

    // answers a token fetch for localhost with a token naming the host, and for 127.0.0.1 with the given status
    private void tokensBy(Approov.TokenFetchStatus secondStatus) {
        sdk.tokenAnswer = url -> {
            boolean first = url.contains("//localhost:");
            Approov.TokenFetchStatus status = first ? Approov.TokenFetchStatus.SUCCESS : secondStatus;
            String token = (status == Approov.TokenFetchStatus.SUCCESS)
                    ? "tok-" + (first ? "localhost" : "127.0.0.1") : null;
            return MiniSdkHook.result(status, token, "trace-" + status, null);
        };
    }

    private static MockResponse redirect(int code, String location) {
        return new MockResponse().setResponseCode(code).setHeader("Location", location).setBody("moved");
    }

    private MiniSdkHttpsOrigins.AppRequest request(int method, byte[] body) {
        return new MiniSdkHttpsOrigins.AppRequest(method, origins.firstUrl("/start") + "?key=" + PLACEHOLDER,
                null, body)
                .header("X-Secret", PLACEHOLDER)
                .header("Authorization", "Bearer app-own")
                .header("X-App", "kept");
    }

    // asserts the first hop was protected as a token-protected request
    private static void assertProtectedFirstHop(RecordedRequest recorded) {
        assertEquals("tok-localhost", recorded.getHeader("Approov-Token"));
        assertEquals(SECRET, recorded.getHeader("X-Secret"));
        assertEquals(SECRET, recorded.getRequestUrl().queryParameter("key"));
        assertNotNull(recorded.getHeader("Signature"));
    }

    @Test
    public void aRedirectToAnotherOriginCarriesNothingTheLayerAdded() throws Exception {
        origins.first.enqueue(redirect(302, origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        HttpResponse response = origins.send(request(Request.Method.GET, null));
        assertEquals(200, response.getStatusCode());

        assertProtectedFirstHop(origins.take(origins.first));
        RecordedRequest hop = origins.take(origins.second);
        assertNotNull("the redirect was not followed", hop);
        MiniSdkHttpsOrigins.assertNoApproovHeaders("cross-origin hop", hop);
        assertEquals("the app's placeholder goes on, never the secret", PLACEHOLDER, hop.getHeader("X-Secret"));
        assertNull("Authorization is dropped on another host, as the platform does", hop.getHeader("Authorization"));
        assertEquals("the app's own headers go on", "kept", hop.getHeader("X-App"));
        assertTrue("the token is fetched for the target",
                sdk.snapshot().contains("fetchApproovTokenAndWait:" + origins.secondUrl("/landing")));
    }

    @Test
    public void aStatusWrittenIntoAPlaceholderIsRestoredOnARedirectToAnotherOrigin() throws Exception {
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.REJECTED, null));
        origins.first.enqueue(redirect(302, origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(Request.Method.GET, null));
        assertEquals("REJECTED", origins.take(origins.first).getHeader("X-Secret"));
        assertEquals(PLACEHOLDER, origins.take(origins.second).getHeader("X-Secret"));
    }

    @Test
    public void aRedirectToASecondProtectedHostCarriesItsOwnToken() throws Exception {
        tokensBy(Approov.TokenFetchStatus.SUCCESS);
        origins.first.enqueue(redirect(302, origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(Request.Method.GET, null));
        assertProtectedFirstHop(origins.take(origins.first));
        RecordedRequest hop = origins.take(origins.second);
        assertEquals("a fresh token for the target", "tok-127.0.0.1", hop.getHeader("Approov-Token"));
        assertEquals("the app's placeholder is substituted for the protected target", SECRET,
                hop.getHeader("X-Secret"));
        assertNotNull("the target is signed", hop.getHeader("Signature"));
        assertTrue(hop.getHeader("Signature-Input"), hop.getHeader("Signature-Input").contains("\"@target-uri\""));
    }

    @Test
    public void aSameOriginRedirectIsProtectedAndSignedAgain() throws Exception {
        origins.first.enqueue(redirect(301, origins.firstUrl("/next")));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(Request.Method.GET, null));
        RecordedRequest first = origins.take(origins.first);
        RecordedRequest hop = origins.take(origins.first);
        assertProtectedFirstHop(first);
        assertEquals("/next", hop.getPath());
        assertEquals("tok-localhost", hop.getHeader("Approov-Token"));
        assertEquals(SECRET, hop.getHeader("X-Secret"));
        assertEquals("Authorization stays on the same origin", "Bearer app-own", hop.getHeader("Authorization"));
        assertNotNull(hop.getHeader("Signature"));
        assertNotEquals("signed over its own URL", first.getHeader("Signature"), hop.getHeader("Signature"));
        assertTrue(sdk.snapshot().contains("fetchApproovTokenAndWait:" + origins.firstUrl("/next")));
    }

    @Test
    public void aSeeOtherTurnsAPostIntoAGetWithoutABodyAndIsSignedAgain() throws Exception {
        for (int code : new int[] {301, 302, 303}) {
            origins.first.enqueue(redirect(code, origins.firstUrl("/result")));
            origins.first.enqueue(MiniSdkHttpsOrigins.ok());
            origins.send(request(Request.Method.POST, "a=1".getBytes(StandardCharsets.UTF_8))
                    .header("Content-Type", "application/x-www-form-urlencoded"));
            RecordedRequest post = origins.take(origins.first);
            RecordedRequest get = origins.take(origins.first);
            assertEquals(code + ": first", "POST", post.getMethod());
            assertEquals(code + ": hop", "GET", get.getMethod());
            assertEquals(code + ": no body", 0, get.getBodySize());
            assertNull(code + ": no Content-Type", get.getHeader("Content-Type"));
            assertEquals(code + ": token", "tok-localhost", get.getHeader("Approov-Token"));
            assertNotEquals(code + ": signed again", post.getHeader("Signature"), get.getHeader("Signature"));
        }
    }

    @Test
    public void aTemporaryRedirectKeepsAGetAndIsNotFollowedForAPost() throws Exception {
        origins.first.enqueue(redirect(307, origins.firstUrl("/temp")));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(request(Request.Method.GET, null)).getStatusCode());
        origins.take(origins.first);
        assertEquals("GET", origins.take(origins.first).getMethod());

        origins.first.enqueue(redirect(308, origins.firstUrl("/perm")));
        HttpResponse response = origins.send(request(Request.Method.POST, "a=1".getBytes(StandardCharsets.UTF_8)));
        assertEquals("a POST is not redirected on 308", 308, response.getStatusCode());
        assertEquals(3, origins.first.getRequestCount());
    }

    @Test
    public void aRedirectToAnotherSchemeIsNotFollowed() throws Exception {
        origins.shutdown();
        start(false);
        origins.first.enqueue(redirect(302, origins.secondUrl("/cleartext")));
        HttpResponse response = origins.send(request(Request.Method.GET, null));
        assertEquals(302, response.getStatusCode());
        assertEquals(0, origins.second.getRequestCount());
    }

    @Test
    public void redirectsAreNotFollowedWhenThePlatformSettingIsOff() throws Exception {
        HttpURLConnection.setFollowRedirects(false);
        origins.first.enqueue(redirect(302, origins.secondUrl("/landing")));
        HttpResponse response = origins.send(request(Request.Method.GET, null));
        assertEquals(302, response.getStatusCode());
        assertEquals(0, origins.second.getRequestCount());
    }

    @Test
    public void atMostTwentyFollowUpsAreMade() throws Exception {
        for (int i = 0; i < 21; i++)
            origins.first.enqueue(redirect(302, origins.firstUrl("/loop" + i)));
        try {
            origins.send(request(Request.Method.GET, null));
            fail("too many follow-ups must fail");
        } catch (ProtocolException e) {
            assertEquals("Too many follow-up requests: 21", e.getMessage());
        }
        assertEquals(21, origins.first.getRequestCount());
    }

    @Test
    public void theTargetURLIsFollowedAsTheServerSentIt() throws Exception {
        // the server's query names a substitution parameter with a value that is a secure string key, and echoes
        // the secret the app's request carried
        String location = origins.firstUrl("/next") + "?key=" + PLACEHOLDER + "&echo=" + SECRET;
        origins.first.enqueue(redirect(302, location));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        int secureStringFetches = sdk.count("fetchSecureStringAndWait");
        origins.send(request(Request.Method.GET, null));
        origins.take(origins.first);
        RecordedRequest hop = origins.take(origins.first);
        assertEquals("the server's query is never substituted", PLACEHOLDER, hop.getRequestUrl().queryParameter("key"));
        assertEquals("an echoed secret is never restored", SECRET, hop.getRequestUrl().queryParameter("echo"));
        // the first hop fetched the header and the query secure strings, the hop the header only
        assertEquals(secureStringFetches + 3, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void anExcludedTargetIsSentUntouched() throws Exception {
        ApproovService.addExclusionURLRegex("/excluded");
        origins.first.enqueue(redirect(302, origins.firstUrl("/excluded")));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(Request.Method.GET, null));
        assertProtectedFirstHop(origins.take(origins.first));
        RecordedRequest hop = origins.take(origins.first);
        MiniSdkHttpsOrigins.assertNoApproovHeaders("excluded hop", hop);
        assertEquals(PLACEHOLDER, hop.getHeader("X-Secret"));
    }

    @Test
    public void everyAttemptOfARequestUsesTheMutatorItStartedWith() throws Exception {
        List<String> seen = Collections.synchronizedList(new ArrayList<String>());
        class Named implements ApproovServiceMutator {
            private final String name;
            private final ApproovServiceMutator next;

            Named(String name, ApproovServiceMutator next) {
                this.name = name;
                this.next = next;
            }

            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                    ApproovRequestMutations changes) {
                seen.add(name + " " + request.getUrl().replaceAll("\\?.*", ""));
                if (next != null)
                    ApproovService.setServiceMutator(next);
                return headers;
            }
        }
        Named second = new Named("second", null);
        ApproovService.setServiceMutator(new Named("first", second));
        origins.first.enqueue(redirect(302, origins.firstUrl("/next")));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        MiniSdkHttpsOrigins.AppRequest request = request(Request.Method.GET, null);
        origins.send(request);
        assertSame("a later request uses the new mutator", second, ApproovService.getServiceMutator());

        // a retry of the same request by Volley also uses the mutator it started with
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        assertEquals(java.util.Arrays.asList("first " + origins.firstUrl("/start"), "first " + origins.firstUrl("/next"),
                "first " + origins.firstUrl("/start")), seen);
        assertFalse(seen.contains("second"));
    }
}
