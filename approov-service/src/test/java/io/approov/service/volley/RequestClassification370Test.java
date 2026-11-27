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

import com.android.volley.Request;
import com.android.volley.VolleyError;
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
 * The token fetch status of a request URL decides what the request carries, on the wire:
 *
 * - SUCCESS (a token-protected API): the token header and the trace header, which replace any value the app
 *   set on the same header names.
 * - UNPROTECTED_URL (a secrets-only API) and UNKNOWN_URL (a host not added to Approov): no Approov header.
 * - any failure status: the mutator's token decision aborts or proceeds, for a listed host only (a key of the
 *   SDK pin set other than "*"). A proceeding request carries the token header with the prefix and an empty
 *   token (or the status name with setUseApproovStatusIfNoToken(true)) and the trace header when the SDK gave
 *   a trace ID. For a host that is not listed, or an empty pin set, the request goes out untouched: a standard
 *   decision's abort is ignored and only the app's own exception aborts it.
 *
 * An empty trace ID is never sent. No request carries a separate status header. An exception from the app's
 * own mutator code reaches the app through Volley as an ApproovException naming the hook, with the original as
 * its cause, while the standard decisions keep their own exception types.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class RequestClassification370Test {
    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    // every token fetch status that is a failure, that is all but SUCCESS, UNKNOWN_URL and UNPROTECTED_URL
    private static List<Approov.TokenFetchStatus> failureStatuses() {
        List<Approov.TokenFetchStatus> statuses = new ArrayList<>();
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            if ((status != Approov.TokenFetchStatus.SUCCESS) && (status != Approov.TokenFetchStatus.UNKNOWN_URL)
                    && (status != Approov.TokenFetchStatus.UNPROTECTED_URL))
                statuses.add(status);
        }
        return statuses;
    }

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    // sends a GET to the first origin and returns what arrived there
    private RecordedRequest sendFirst(Request<?> request) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    private MiniSdkHttpsOrigins.AppRequest request() {
        return new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/data"));
    }

    @Test
    public void successAddsTheTokenAndTraceHeaders() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        RecordedRequest recorded = sendFirst(request());
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("trace-1", recorded.getHeader("Approov-TraceID"));
        assertNull("there is no status header", recorded.getHeader("Approov-Status"));
    }

    @Test
    public void theTokenHeaderReplacesAnAppSetValueWhateverItsCase() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        RecordedRequest recorded = sendFirst(request().header("approov-token", "forged").header("approov-traceid", "x"));
        assertEquals(Collections.singletonList("jwt-token"), recorded.getHeaders().values("Approov-Token"));
        assertEquals(Collections.singletonList("trace-1"), recorded.getHeaders().values("Approov-TraceID"));
    }

    @Test
    public void anEmptyTraceIDIsNeverSent() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "");
        RecordedRequest recorded = sendFirst(request());
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertNull(recorded.getHeader("Approov-TraceID"));

        sdk.answerTokens(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "");
        recorded = sendFirst(request());
        assertEquals("", recorded.getHeader("Approov-Token"));
        assertNull(recorded.getHeader("Approov-TraceID"));
    }

    @Test
    public void closeFailureSendsNoApproovServiceToAListedHostWithAnEmptyToken() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "trace-nas");
        RecordedRequest recorded = sendFirst(request());
        assertEquals("", recorded.getHeader("Approov-Token"));
        assertEquals("trace-nas", recorded.getHeader("Approov-TraceID"));

        ApproovService.setTokenHeader("Authorization", "Bearer ");
        recorded = sendFirst(request());
        assertEquals("Bearer", recorded.getHeader("Authorization").trim());
        assertTrue(recorded.getHeader("Authorization").startsWith("Bearer"));

        ApproovService.setUseApproovStatusIfNoToken(true);
        recorded = sendFirst(request());
        assertEquals("Bearer NO_APPROOV_SERVICE", recorded.getHeader("Authorization"));
    }

    // one row per failure status, under both standard mutators, with the status in the token header off and on
    @Test
    public void perStatusTokenTable() throws Exception {
        ApproovServiceMutator[] mutators = {ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED};
        for (ApproovServiceMutator mutator : mutators) {
            for (boolean useStatus : new boolean[] {false, true}) {
                for (Approov.TokenFetchStatus status : failureStatuses()) {
                    String what = mutator + (useStatus ? " status on " : " status off ") + status;
                    ApproovService.setServiceMutator(mutator);
                    ApproovService.setUseApproovStatusIfNoToken(useStatus);
                    sdk.answerTokens(status, null, "trace-" + status);
                    boolean network = ApproovServiceMutator.isNetworkFailure(status);
                    boolean proceeds = (mutator == ApproovServiceMutator.ALWAYS_PROCEED)
                            || (status == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) || (network && useStatus);
                    if (proceeds) {
                        RecordedRequest recorded = sendFirst(request());
                        assertEquals(what, useStatus ? status.name() : "", recorded.getHeader("Approov-Token"));
                        assertEquals(what, "trace-" + status, recorded.getHeader("Approov-TraceID"));
                        assertNull(what, recorded.getHeader("Approov-Status"));
                    } else {
                        int before = origins.first.getRequestCount();
                        try {
                            origins.send(request());
                            fail(what + ": must abort");
                        } catch (ApproovFetchStatusException e) {
                            assertEquals(what, network ? ApproovNetworkException.class : ApproovFetchStatusException.class,
                                    e.getClass());
                            assertSame(what, status, e.getTokenFetchStatus());
                            assertEquals(what, "Approov token fetch for " + origins.firstUrl("/data") + ": " + status,
                                    e.getMessage());
                        }
                        assertEquals(what + ": nothing sent", before, origins.first.getRequestCount());
                    }
                }
            }
        }
    }

    // one row per token fetch status of every kind, under both standard decisions with a signer installed and
    // the status in the token header off and on: what the token header, the signature headers and the
    // placeholders of a header and a query parameter hold on the wire, with a secret at hand to show a leak
    @Test
    public void perStatusTokenTableCoversPlaceholdersAndSignatures() throws Exception {
        final String placeholder = "api-key-placeholder";
        final String secret = "real-api-key-value";
        sdk.secureStrings.put(placeholder, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, secret));
        ApproovService.addSubstitutionHeader("X-Secret", null);
        ApproovService.addSubstitutionQueryParam("key");
        ApproovServiceMutator[] decisions = {ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED};
        for (ApproovServiceMutator decision : decisions) {
            for (boolean useStatus : new boolean[] {false, true}) {
                for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                    if (status == Approov.TokenFetchStatus.UNKNOWN_KEY)
                        continue; // a secure string status only, never answered to a token fetch
                    String what = decision + (useStatus ? " status on " : " status off ") + status;
                    ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(decision));
                    ApproovService.setUseApproovStatusIfNoToken(useStatus);
                    sdk.answerTokens(status, (status == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token" : null,
                            "trace-" + status);
                    int secureStringFetches = sdk.count("fetchSecureStringAndWait");
                    boolean failure = failureStatuses().contains(status);
                    boolean network = ApproovServiceMutator.isNetworkFailure(status);
                    boolean aborts = failure && (decision == ApproovServiceMutator.CLOSE_FAILURE)
                            && (status != Approov.TokenFetchStatus.NO_APPROOV_SERVICE) && !(network && useStatus);
                    MiniSdkHttpsOrigins.AppRequest app = new MiniSdkHttpsOrigins.AppRequest(
                            origins.firstUrl("/data") + "?key=" + placeholder).header("X-Secret", placeholder);
                    if (aborts) {
                        int before = origins.first.getRequestCount();
                        try {
                            origins.send(app);
                            fail(what + ": must abort");
                        } catch (ApproovFetchStatusException expected) {
                            assertSame(what, status, expected.getTokenFetchStatus());
                        }
                        assertEquals(what + ": nothing sent", before, origins.first.getRequestCount());
                        assertEquals(what + ": no secure string fetched", secureStringFetches,
                                sdk.count("fetchSecureStringAndWait"));
                        continue;
                    }
                    RecordedRequest recorded = sendFirst(app);
                    boolean secrets = (status == Approov.TokenFetchStatus.SUCCESS)
                            || (status == Approov.TokenFetchStatus.UNPROTECTED_URL);
                    boolean token = (status == Approov.TokenFetchStatus.SUCCESS) || failure;
                    // the placeholders: the secret on a protected channel, as the app wrote them anywhere else
                    String value = secrets ? secret : placeholder;
                    assertEquals(what + ": header", value, recorded.getHeader("X-Secret"));
                    assertEquals(what + ": query", value, recorded.getRequestUrl().queryParameter("key"));
                    assertEquals(what + ": secure strings fetched", secrets, sdk.count("fetchSecureStringAndWait")
                            > secureStringFetches);
                    // the token header and the trace header
                    String expectedToken = (status == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token"
                            : (failure ? (useStatus ? status.name() : "") : null);
                    assertEquals(what + ": token header", expectedToken, recorded.getHeader("Approov-Token"));
                    assertEquals(what + ": trace header", token ? "trace-" + status : null,
                            recorded.getHeader("Approov-TraceID"));
                    assertNull(what, recorded.getHeader("Approov-Status"));
                    // the signature covers the token header where there is one, and is absent otherwise
                    if (token) {
                        String input = recorded.getHeader("Signature-Input");
                        assertNotNull(what + ": Signature-Input", input);
                        assertNotNull(what + ": Signature", recorded.getHeader("Signature"));
                        assertTrue(what + ": " + input, input.contains("\"approov-token\""));
                    } else {
                        assertNull(what + ": Signature-Input", recorded.getHeader("Signature-Input"));
                        assertNull(what + ": Signature", recorded.getHeader("Signature"));
                    }
                }
            }
        }
    }

    @Test
    public void aProceedingFailureIsSignedOverTheTokenHeaderAsSent() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        sdk.answerTokens(Approov.TokenFetchStatus.NO_NETWORK, null, "trace-nn");
        RecordedRequest recorded = sendFirst(request());
        assertEquals("", recorded.getHeader("Approov-Token"));
        String input = recorded.getHeader("Signature-Input");
        assertNotNull("Signature-Input", input);
        assertNotNull("Signature", recorded.getHeader("Signature"));
        assertTrue(input, input.contains("\"approov-token\""));
    }

    @Test
    public void aFailureForAHostThatIsNotListedGoesOutUntouched() throws Exception {
        for (Map<String, List<String>> pins : new ArrayList<Map<String, List<String>>>() {{
                add(Collections.singletonMap("api.example.com", Collections.<String>emptyList()));
                add(Collections.singletonMap("*", Collections.singletonList("AAAA")));
                add(Collections.<String, List<String>>emptyMap());
        }}) {
            sdk.pins = pins;
            for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                    Approov.TokenFetchStatus.REJECTED, Approov.TokenFetchStatus.NO_NETWORK,
                    Approov.TokenFetchStatus.NO_APPROOV_SERVICE}) {
                sdk.answerTokens(status, null, "trace-" + status);
                RecordedRequest recorded = sendFirst(request());
                MiniSdkHttpsOrigins.assertNoApproovHeaders(pins + " " + status, recorded);
            }
        }
    }

    @Test
    public void aListedHostIsMatchedWithoutRegardToCaseAndOneTrailingDot() throws Exception {
        sdk.pins = Collections.singletonMap("LOCALHOST.", Collections.<String>emptyList());
        sdk.answerTokens(Approov.TokenFetchStatus.NO_APPROOV_SERVICE, null, "trace-nas");
        RecordedRequest recorded = sendFirst(request());
        assertEquals("", recorded.getHeader("Approov-Token"));
    }

    @Test
    public void onlyTheAppsOwnThrowAbortsAFailureForAHostThatIsNotListed() throws Exception {
        sdk.pins = Collections.emptyMap();
        sdk.answerTokens(Approov.TokenFetchStatus.REJECTED, null, "trace-r");

        // the inherited standard decision throws, which is ignored
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
        });
        MiniSdkHttpsOrigins.assertNoApproovHeaders("inherited", sendFirst(request()));

        // a custom mutator calling the standard decision, which is still a standard decision
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult results, String url)
                    throws ApproovException {
                return ApproovServiceMutator.CLOSE_FAILURE.handleRequestFetchTokenResult(results, url);
            }
        });
        MiniSdkHttpsOrigins.assertNoApproovHeaders("called", sendFirst(request()));

        // true sends it untouched too
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult results, String url) {
                return true;
            }
        });
        MiniSdkHttpsOrigins.assertNoApproovHeaders("true", sendFirst(request()));

        // the app's own exception aborts it, as a hook failure with the original as its cause
        ApproovException own = new ApproovException("only my own hosts");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult results, String url)
                    throws ApproovException {
                throw own;
            }
        });
        int before = origins.first.getRequestCount();
        try {
            origins.send(request());
            fail("the app's own exception must abort the request");
        } catch (ApproovException e) {
            assertEquals(ApproovException.class, e.getClass());
            assertTrue(e.getMessage(), e.getMessage().startsWith(
                    "ApproovServiceMutator.handleRequestFetchTokenResult failed: "));
            assertSame(own, e.getCause());
        }
        assertEquals("nothing sent", before, origins.first.getRequestCount());
    }

    @Test
    public void unknownAndUnprotectedURLsCarryNoApproovHeader() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED));
        ApproovService.setUseApproovStatusIfNoToken(true);
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.UNPROTECTED_URL}) {
            sdk.answerTokens(status, null, "trace-" + status);
            MiniSdkHttpsOrigins.assertNoApproovHeaders(status.name(), sendFirst(request()));
        }
    }

    @Test
    public void anExcludedURLIsNotProcessed() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ApproovService.addExclusionURLRegex("/excluded");
        int fetches = sdk.count("fetchApproovTokenAndWait");
        RecordedRequest recorded = sendFirst(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/excluded")));
        MiniSdkHttpsOrigins.assertNoApproovHeaders("excluded", recorded);
        assertEquals("no token fetch", fetches, sdk.count("fetchApproovTokenAndWait"));
    }

    @Test
    public void anExceptionFromTheAppsMutatorIsAHookFailureWithTheOriginalAsCause() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        IllegalStateException bug = new IllegalStateException("bug in the app");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders) {
                throw bug;
            }
        });
        VolleyError error = origins.perform(request());
        assertNotNull("must fail", error);
        assertEquals(ApproovException.class, error.getClass());
        assertTrue(error.getMessage(), error.getMessage().startsWith(
                "ApproovServiceMutator.handleRequestShouldProcess failed: "));
        assertSame(bug, error.getCause());

        ApproovException own = new ApproovNetworkException("my own policy");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                    ApproovRequestMutations changes) throws ApproovException {
                throw own;
            }
        });
        error = origins.perform(request());
        assertNotNull("must fail", error);
        assertEquals(ApproovException.class, error.getClass());
        assertTrue(error.getMessage(), error.getMessage().startsWith(
                "ApproovServiceMutator.handleRequestProcessedHeaders failed: "));
        assertSame(own, error.getCause());
        assertEquals("nothing sent", 0, origins.first.getRequestCount());
    }

    @Test
    public void aStandardDecisionKeepsItsTypeThroughVolley() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.REJECTED, null, "trace-r");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult results, String url)
                    throws ApproovException {
                return ApproovServiceMutator.super.handleRequestFetchTokenResult(results, url);
            }
        });
        VolleyError error = origins.perform(request());
        assertNotNull("must fail", error);
        assertEquals(ApproovFetchStatusException.class, error.getClass());
        assertSame(Approov.TokenFetchStatus.REJECTED, ((ApproovFetchStatusException) error).getTokenFetchStatus());
    }

    @Test
    public void aRuntimeExceptionFromTheSdkFailsTheRequestAsAnApproovException() throws Exception {
        IllegalStateException sdkFailure = new IllegalStateException("sdk broke");
        sdk.tokenAnswer = url -> {
            throw sdkFailure;
        };
        VolleyError error = origins.perform(request());
        assertNotNull("must fail", error);
        assertEquals(ApproovException.class, error.getClass());
        assertSame(sdkFailure, error.getCause());
        assertEquals("", ApproovService.getLastARC());
        assertEquals("nothing sent", 0, origins.first.getRequestCount());
    }
}
