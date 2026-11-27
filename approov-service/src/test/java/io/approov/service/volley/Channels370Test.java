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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * What each channel receives, checked on the wire with the mini SDK answering where it can: a cleartext
 * request is a BAD_URL for the SDK, which a standard abort stops for a listed host before anything is sent
 * and ignores for any other host; no secure string is fetched or substituted on UNKNOWN_URL, a cleartext
 * request, BAD_URL or a proceeding failure, for any decision, on the request and on a redirect hop, whether
 * the host is in the pin set or not; and SUCCESS needs no pin set entry to be token-protected.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class Channels370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    private void start(boolean secondOverTls, String... listed) throws Exception {
        origins = new MiniSdkHttpsOrigins(secondOverTls);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts(listed);
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, SECRET));
        ApproovService.addSubstitutionHeader("X-Secret", null);
        ApproovService.addSubstitutionQueryParam("key");
    }

    @After
    public void tearDown() throws Exception {
        if (origins != null)
            origins.shutdown();
    }

    private MiniSdkHttpsOrigins.AppRequest request(String url) {
        return new MiniSdkHttpsOrigins.AppRequest(url + "?key=" + PLACEHOLDER).header("X-Secret", PLACEHOLDER);
    }

    private static void assertPlaceholders(String what, RecordedRequest recorded) {
        assertNotNull(what + ": not delivered", recorded);
        assertEquals(what + ": header", PLACEHOLDER, recorded.getHeader("X-Secret"));
        assertEquals(what + ": query", PLACEHOLDER, recorded.getRequestUrl().queryParameter("key"));
    }

    private static ApproovServiceMutator[] mutators() {
        return new ApproovServiceMutator[] {ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED,
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE),
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)};
    }

    @Test
    public void cleartextToAListedHostIsRefusedByCloseFailureBeforeAnythingIsSent() throws Exception {
        start(false, "localhost", "127.0.0.1");
        ApproovService.setServiceMutator(ApproovServiceMutator.CLOSE_FAILURE);
        try {
            origins.send(request(origins.secondUrl("/data")));
            fail("a cleartext request to a listed host must fail");
        } catch (ApproovFetchStatusException e) {
            assertSame(Approov.TokenFetchStatus.BAD_URL, e.getTokenFetchStatus());
            assertTrue(e.getMessage(), e.getMessage().startsWith("Approov token fetch for http://127.0.0.1:"));
            assertTrue(e.getMessage(), e.getMessage().endsWith(": BAD_URL"));
        }
        assertEquals("nothing on the wire", 0, origins.second.getRequestCount());
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void cleartextToAListedHostIsDeliveredByAlwaysProceedWithNoSecureString() throws Exception {
        start(false, "localhost", "127.0.0.1");
        ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(origins.secondUrl("/data")));
        assertPlaceholders("http, listed", origins.take(origins.second));
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void cleartextToAHostThatIsNotListedIsNeverBlocked() throws Exception {
        start(false, "localhost");
        for (ApproovServiceMutator mutator : mutators()) {
            ApproovService.setServiceMutator(mutator);
            origins.second.enqueue(MiniSdkHttpsOrigins.ok());
            origins.send(request(origins.secondUrl("/data")));
            RecordedRequest recorded = origins.take(origins.second);
            assertPlaceholders(mutator.toString(), recorded);
            MiniSdkHttpsOrigins.assertNoApproovHeaders(mutator.toString(), recorded);
        }
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void noSecureStringIsSentOnAnyChannelThatAllowsNone() throws Exception {
        start(true, "localhost");
        Approov.TokenFetchStatus[] statuses = {Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.BAD_URL,
                Approov.TokenFetchStatus.NO_APPROOV_SERVICE, Approov.TokenFetchStatus.NO_NETWORK,
                Approov.TokenFetchStatus.REJECTED};
        for (ApproovServiceMutator mutator : mutators()) {
            for (Approov.TokenFetchStatus status : statuses) {
                // listed (localhost) and not listed (127.0.0.1), each with the status answered
                for (boolean listed : new boolean[] {true, false}) {
                    String what = mutator + " " + status + (listed ? " listed" : " not listed");
                    ApproovService.setServiceMutator(mutator);
                    sdk.answerTokens(status, null, "trace-x");
                    boolean aborts = listed && (mutator.toString().contains("CLOSE_FAILURE")
                            || mutator == ApproovServiceMutator.CLOSE_FAILURE)
                            && (status != Approov.TokenFetchStatus.UNKNOWN_URL)
                            && (status != Approov.TokenFetchStatus.NO_APPROOV_SERVICE);
                    String url = listed ? origins.firstUrl("/data") : origins.secondUrl("/data");
                    okhttp3.mockwebserver.MockWebServer server = listed ? origins.first : origins.second;
                    if (aborts) {
                        try {
                            origins.send(request(url));
                            fail(what + ": must abort");
                        } catch (ApproovException expected) {
                            // no secure string is fetched for an aborted request either
                        }
                    } else {
                        server.enqueue(MiniSdkHttpsOrigins.ok());
                        origins.send(request(url));
                        assertPlaceholders(what, origins.take(server));
                    }
                }
            }
        }
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void aRedirectHopOnAFailureStatusCarriesNoSecureString() throws Exception {
        start(true, "localhost", "127.0.0.1");
        for (ApproovServiceMutator mutator : new ApproovServiceMutator[] {ApproovServiceMutator.ALWAYS_PROCEED,
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)}) {
            ApproovService.setServiceMutator(mutator);
            // the first hop is token protected, the target answers a failure
            sdk.tokenAnswer = url -> url.contains("//localhost:")
                    ? MiniSdkHook.result(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1", null)
                    : MiniSdkHook.result(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-2", null);
            origins.first.enqueue(new MockResponse().setResponseCode(302)
                    .setHeader("Location", origins.secondUrl("/landing")));
            origins.second.enqueue(MiniSdkHttpsOrigins.ok());
            int before = sdk.count("fetchSecureStringAndWait");
            origins.send(request(origins.firstUrl("/data")));
            assertEquals(mutator + ": the first hop is substituted", SECRET, origins.take(origins.first)
                    .getHeader("X-Secret"));
            RecordedRequest hop = origins.take(origins.second);
            assertNotNull(hop);
            assertEquals(mutator + ": the hop keeps the app's placeholder", PLACEHOLDER, hop.getHeader("X-Secret"));
            assertEquals(mutator + ": only the first hop fetched secure strings", before + 2,
                    sdk.count("fetchSecureStringAndWait"));
        }
    }

    @Test
    public void successNeedsNoPinSetEntryAndGetsTokenSecretsAndSignature() throws Exception {
        start(true);
        for (ApproovServiceMutator mutator : new ApproovServiceMutator[] {
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE),
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)}) {
            ApproovService.setServiceMutator(mutator);
            sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
            origins.first.enqueue(MiniSdkHttpsOrigins.ok());
            origins.send(request(origins.firstUrl("/data")));
            RecordedRequest recorded = origins.take(origins.first);
            assertEquals(mutator.toString(), "jwt-token", recorded.getHeader("Approov-Token"));
            assertEquals(mutator.toString(), SECRET, recorded.getHeader("X-Secret"));
            assertEquals(mutator.toString(), SECRET, recorded.getRequestUrl().queryParameter("key"));
            assertNotNull(mutator.toString(), recorded.getHeader("Signature"));
        }
    }

    @Test
    public void aFailureWithAnEmptyPinSetIsNeverAbortedAndGoesOutUntouched() throws Exception {
        start(true);
        for (ApproovServiceMutator mutator : mutators()) {
            ApproovService.setServiceMutator(mutator);
            sdk.answerTokens(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-x");
            origins.first.enqueue(MiniSdkHttpsOrigins.ok());
            origins.send(request(origins.firstUrl("/data")));
            RecordedRequest recorded = origins.take(origins.first);
            assertPlaceholders(mutator.toString(), recorded);
            assertNull(mutator.toString(), recorded.getHeader("Approov-Token"));
            assertNull(mutator.toString(), recorded.getHeader("Approov-TraceID"));
        }
    }
}
