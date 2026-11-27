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
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * Secure strings are substituted only on a protected channel: a token fetch of SUCCESS (a token-protected API)
 * or UNPROTECTED_URL (a secrets-only API), over https. There, under both standard mutators, a SUCCESS replaces
 * the placeholder with the secure string, after any required prefix, and every other secure string status but
 * UNKNOWN_KEY writes the status name in its place (Bearer REJECTED); UNKNOWN_KEY leaves the value as the app
 * wrote it, as the value is not a secure string key. No secure string status aborts a request under a standard
 * mutator. On UNKNOWN_URL, http, BAD_URL and a proceeding failure status no secure string is fetched and every
 * placeholder goes out as the app wrote it. The manual helpers follow the same rules.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SecureStrings370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(false);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost", "127.0.0.1");
        configure();
    }

    // the configuration of every test, made after initialize since initialize resets it
    private static void configure() {
        ApproovService.addSubstitutionHeader("Api-Key", null);
        ApproovService.addSubstitutionHeader("Authorization", "Bearer ");
        ApproovService.addSubstitutionQueryParam("key");
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private MiniSdkHttpsOrigins.AppRequest request(String url) {
        return new MiniSdkHttpsOrigins.AppRequest(url + "?key=" + PLACEHOLDER)
                .header("Api-Key", PLACEHOLDER).header("Authorization", "Bearer " + PLACEHOLDER);
    }

    private MiniSdkHttpsOrigins.AppRequest request() {
        return request(origins.firstUrl("/data"));
    }

    private RecordedRequest sendFirst(Request<?> request) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request);
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }

    private void answerSecureStrings(Approov.TokenFetchStatus status, String value) {
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(status, value));
    }

    // asserts the three placeholders arrived as the app wrote them
    private static void assertPlaceholders(String what, RecordedRequest recorded) {
        assertEquals(what + ": header", PLACEHOLDER, recorded.getHeader("Api-Key"));
        assertEquals(what + ": prefixed header", "Bearer " + PLACEHOLDER, recorded.getHeader("Authorization"));
        assertEquals(what + ": query", PLACEHOLDER, recorded.getRequestUrl().queryParameter("key"));
    }

    // asserts the three placeholders arrived carrying the value
    private static void assertSubstituted(String what, String value, RecordedRequest recorded) {
        assertEquals(what + ": header", value, recorded.getHeader("Api-Key"));
        assertEquals(what + ": prefixed header", "Bearer " + value, recorded.getHeader("Authorization"));
        assertEquals(what + ": query", value, recorded.getRequestUrl().queryParameter("key"));
    }

    @Test
    public void aTokenProtectedAPIGetsItsSecureStrings() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        RecordedRequest recorded = sendFirst(request());
        assertSubstituted("SUCCESS", SECRET, recorded);
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
    }

    @Test
    public void aSecretsOnlyAPIGetsItsSecureStringsAndNoApproovHeader() throws Exception {
        for (ApproovServiceMutator decisions : new ApproovServiceMutator[] {
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED}) {
            ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(decisions));
            sdk.answerTokens(Approov.TokenFetchStatus.UNPROTECTED_URL, null, "trace-u");
            answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
            RecordedRequest recorded = sendFirst(request());
            assertSubstituted(decisions.toString(), SECRET, recorded);
            MiniSdkHttpsOrigins.assertNoApproovHeaders(decisions.toString(), recorded);
        }
    }

    // one row per secure string status, under both standard mutators, on both protected channels
    @Test
    public void perStatusSecureStringTable() throws Exception {
        for (ApproovServiceMutator mutator : new ApproovServiceMutator[] {
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED}) {
            for (Approov.TokenFetchStatus channel : new Approov.TokenFetchStatus[] {
                    Approov.TokenFetchStatus.SUCCESS, Approov.TokenFetchStatus.UNPROTECTED_URL}) {
                for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                    String what = mutator + " " + channel + " secure string " + status;
                    ApproovService.setServiceMutator(mutator);
                    sdk.answerTokens(channel, (channel == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token" : null,
                            "trace-1");
                    answerSecureStrings(status, (status == Approov.TokenFetchStatus.SUCCESS) ? SECRET : null);
                    RecordedRequest recorded = sendFirst(request());
                    if (status == Approov.TokenFetchStatus.SUCCESS)
                        assertSubstituted(what, SECRET, recorded);
                    else if (status == Approov.TokenFetchStatus.UNKNOWN_KEY)
                        assertPlaceholders(what, recorded);
                    else
                        assertSubstituted(what, status.name(), recorded);
                    // the token header reports the token fetch only
                    assertEquals(what, (channel == Approov.TokenFetchStatus.SUCCESS) ? "jwt-token" : null,
                            recorded.getHeader("Approov-Token"));
                }
            }
        }
    }

    @Test
    public void noSecureStringIsFetchedWithoutAProtectedChannel() throws Exception {
        // a custom mutator that accepts every substitution and every token fetch result
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult results, String url) {
                return true;
            }

            @Override
            public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult results, String header) {
                return true;
            }

            @Override
            public boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult results, String key) {
                return true;
            }
        });
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.NO_APPROOV_SERVICE,
                Approov.TokenFetchStatus.NO_NETWORK, Approov.TokenFetchStatus.REJECTED}) {
            sdk.answerTokens(status, null, "trace-x");
            RecordedRequest recorded = sendFirst(request());
            assertPlaceholders(status.name(), recorded);
        }

        // a cleartext request, which the SDK reports as BAD_URL, to a listed host
        sdk.tokenAnswer = url -> MiniSdkHook.result(url.startsWith("https:") ? Approov.TokenFetchStatus.SUCCESS
                : Approov.TokenFetchStatus.BAD_URL, null, "trace-b", null);
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request(origins.secondUrl("/data")));
        RecordedRequest recorded = origins.take(origins.second);
        assertPlaceholders("http", recorded);
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void aCustomMutatorDecidesEachSubstitution() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        List<ApproovRequestMutations> seen = new java.util.ArrayList<>();
        class Custom implements ApproovServiceMutator {
            boolean answer;

            @Override
            public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult results, String header) {
                return answer;
            }

            @Override
            public boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult results, String key) {
                return answer;
            }

            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                    ApproovRequestMutations changes) {
                seen.add(changes);
                return headers;
            }
        }
        Custom custom = new Custom();
        ApproovService.setServiceMutator(custom);

        // a declined SUCCESS keeps the placeholder
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        custom.answer = false;
        assertPlaceholders("declined", sendFirst(request()));

        // true for a failure status is treated as false, so the status is written
        answerSecureStrings(Approov.TokenFetchStatus.REJECTED, null);
        custom.answer = true;
        assertSubstituted("true on REJECTED", "REJECTED", sendFirst(request()));
        ApproovRequestMutations statusChanges = seen.get(seen.size() - 1);
        assertNull("a status is not a substituted secure string", statusChanges.getSubstitutionHeaderKeys());
        assertNull("a status is not a substituted secure string", statusChanges.getSubstitutionQueryParamKeys());

        // the mutations record the real secure strings only
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        assertSubstituted("accepted", SECRET, sendFirst(request()));
        ApproovRequestMutations changes = seen.get(seen.size() - 1);
        assertEquals(new java.util.HashSet<>(Arrays.asList("Api-Key", "Authorization")),
                new java.util.HashSet<>(changes.getSubstitutionHeaderKeys()));
        assertEquals(Collections.singletonList("key"), changes.getSubstitutionQueryParamKeys());
        assertEquals(origins.firstUrl("/data") + "?key=" + PLACEHOLDER, changes.getOriginalURL());

        // the app's own exception from a substitution hook aborts the request
        ApproovException own = new ApproovException("no secrets for you");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult results, String header)
                    throws ApproovException {
                throw own;
            }
        });
        int before = origins.first.getRequestCount();
        try {
            origins.send(request());
            fail("the app's own exception must abort the request");
        } catch (ApproovException e) {
            assertSame(own, e.getCause());
        }
        assertEquals("nothing sent", before, origins.first.getRequestCount());
    }

    @Test
    public void aValueTheStackCannotCarryKeepsThePlaceholder() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, "line\nbreak&more");
        RecordedRequest recorded = sendFirst(request());
        assertPlaceholders("uncarriable", recorded);
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
    }

    @Test
    public void everyOccurrenceOfAQueryParameterIsSubstitutedOnItsOwn() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        sdk.secureStrings.put("first-key", MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, "first-secret"));
        sdk.secureStrings.put("second-key", MiniSdkHook.secureString(Approov.TokenFetchStatus.REJECTED, null));
        RecordedRequest recorded = sendFirst(new MiniSdkHttpsOrigins.AppRequest(
                origins.firstUrl("/data") + "?key=first-key&other=1&key=second-key&mykey=first-key"));
        assertEquals(Arrays.asList("first-secret", "REJECTED"), recorded.getRequestUrl().queryParameterValues("key"));
        assertEquals("a longer name is another parameter", "first-key",
                recorded.getRequestUrl().queryParameter("mykey"));
    }

    @Test
    public void substitutionHeadersAndQueryParametersCanBeRemoved() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        assertEquals(Collections.singletonMap("key", "key"),
                Collections.singletonMap("key", ApproovService.getSubstitutionQueryParams().keySet().iterator().next()));
        assertEquals("Bearer ", ApproovService.getSubstitutionHeaders().get("Authorization"));
        ApproovService.removeSubstitutionHeader("api-key");
        ApproovService.removeSubstitutionHeader("AUTHORIZATION");
        ApproovService.removeSubstitutionQueryParam("key");
        assertPlaceholders("removed", sendFirst(request()));
    }

    @Test
    public void theHelpersSubstituteOnBothProtectedChannels() throws Exception {
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        for (Approov.TokenFetchStatus channel : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.SUCCESS, Approov.TokenFetchStatus.UNPROTECTED_URL}) {
            sdk.answerTokens(channel, null, null);
            String url = origins.firstUrl("/data");
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Authorization", "Bearer " + PLACEHOLDER);
            ApproovService.substituteHeader(url, headers, "Authorization", "Bearer ");
            assertEquals(channel.name(), "Bearer " + SECRET, headers.get("Authorization"));

            Map<String, String> params = new LinkedHashMap<>();
            params.put("form", PLACEHOLDER);
            ApproovService.substituteQueryParam(url, params, "form");
            assertEquals(channel.name(), SECRET, params.get("form"));

            assertEquals(channel.name(), url + "?key=" + SECRET + "&key=" + SECRET,
                    ApproovService.substituteQueryParamInURLString(url + "?key=" + PLACEHOLDER + "&key=" + PLACEHOLDER,
                            "key"));
        }
    }

    @Test
    public void theHelpersWriteTheStatusAndNeverAbort() throws Exception {
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, null, null);
        String url = origins.firstUrl("/data");
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.REJECTED, Approov.TokenFetchStatus.NO_NETWORK,
                Approov.TokenFetchStatus.UNKNOWN_KEY}) {
            answerSecureStrings(status, null);
            String expected = (status == Approov.TokenFetchStatus.UNKNOWN_KEY) ? PLACEHOLDER : status.name();
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Authorization", "Bearer " + PLACEHOLDER);
            ApproovService.substituteHeader(url, headers, "Authorization", "Bearer ");
            assertEquals(status.name(), "Bearer " + expected, headers.get("Authorization"));

            Map<String, String> params = new LinkedHashMap<>();
            params.put("form", PLACEHOLDER);
            ApproovService.substituteQueryParam(url, params, "form");
            assertEquals(status.name(), expected, params.get("form"));

            assertEquals(status.name(), url + "?key=" + expected,
                    ApproovService.substituteQueryParamInURLString(url + "?key=" + PLACEHOLDER, "key"));
        }
    }

    @Test
    public void theHelpersFetchNoSecureStringWithoutAProtectedChannel() throws Exception {
        answerSecureStrings(Approov.TokenFetchStatus.SUCCESS, SECRET);
        String[] urls = {origins.firstUrl("/data"), origins.secondUrl("/data")};
        for (Approov.TokenFetchStatus status : new Approov.TokenFetchStatus[] {
                Approov.TokenFetchStatus.UNKNOWN_URL, Approov.TokenFetchStatus.NO_APPROOV_SERVICE,
                Approov.TokenFetchStatus.NO_NETWORK, Approov.TokenFetchStatus.BAD_URL}) {
            for (String url : urls) {
                sdk.answerTokens(status, null, null);
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("Api-Key", PLACEHOLDER);
                ApproovService.substituteHeader(url, headers, "Api-Key", null);
                assertEquals(status + " " + url, PLACEHOLDER, headers.get("Api-Key"));
                assertEquals(status + " " + url, url + "?key=" + PLACEHOLDER,
                        ApproovService.substituteQueryParamInURLString(url + "?key=" + PLACEHOLDER, "key"));
            }
        }
        // and nothing on a successful token fetch over cleartext either
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, null, null);
        Map<String, String> params = new LinkedHashMap<>();
        params.put("form", PLACEHOLDER);
        ApproovService.substituteQueryParam(origins.secondUrl("/data"), params, "form");
        assertEquals(PLACEHOLDER, params.get("form"));
        assertEquals("no secure string fetched", 0, sdk.count("fetchSecureStringAndWait"));
    }

    @Test
    public void aSubstitutionHeaderCannotBeTheBindingHeader() {
        ApproovService.setBindingHeader("X-Bound");
        try {
            ApproovService.addSubstitutionHeader("x-bound", null);
            fail("the binding header cannot be substituted");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("x-bound"));
        }
        try {
            ApproovService.setBindingHeader("API-KEY");
            fail("a substitution header cannot be the binding header");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("API-KEY"));
        }
    }
}
