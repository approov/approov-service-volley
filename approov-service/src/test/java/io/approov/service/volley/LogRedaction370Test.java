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

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * No log line carries a substituted secure string, a placeholder or any query value, at the most verbose
 * level. A request whose URL holds a substituted query parameter is logged by its token fetch and its
 * redirects, and those lines show the URL without its query.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class LogRedaction370Test {
    private static final String PLACEHOLDER = "api-key-placeholder";
    private static final String SECRET = "real-api-key-value";

    private MiniSdkHttpsOrigins origins;
    private MiniSdkHook sdk;

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        sdk.tokenAnswer = url -> MiniSdkHook.result(url.contains("//localhost:")
                ? Approov.TokenFetchStatus.SUCCESS : Approov.TokenFetchStatus.UNKNOWN_URL,
                url.contains("//localhost:") ? "jwt-token" : null, "trace-1", null);
        sdk.secureStrings.put(PLACEHOLDER, MiniSdkHook.secureString(Approov.TokenFetchStatus.SUCCESS, SECRET));
        ApproovService.addSubstitutionHeader("X-Secret", null);
        ApproovService.addSubstitutionQueryParam("key");
        // redaction is checked at the most verbose level, the loggable token included
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        ShadowLog.reset();
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private MiniSdkHttpsOrigins.AppRequest request() {
        return new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/data") + "?key=" + PLACEHOLDER)
                .header("X-Secret", PLACEHOLDER);
    }

    // asserts that no log line holds the secret or the placeholder, and that some line mentions the text given
    private static void assertNoValueLoggedAnd(String logged) {
        boolean found = false;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            assertFalse("secret logged: " + item.msg, item.msg.contains(SECRET));
            assertFalse("placeholder logged: " + item.msg, item.msg.contains(PLACEHOLDER));
            found |= item.msg.contains(logged);
        }
        assertTrue("no line with: " + logged, found);
    }

    @Test
    public void aRequestWithASubstitutedQueryIsLoggedWithoutTheSecret() throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request());
        RecordedRequest recorded = origins.take(origins.first);
        assertEquals("control: substituted", SECRET, recorded.getRequestUrl().queryParameter("key"));
        // the token line names the URL the token was fetched for, which holds the secret in its query
        assertNoValueLoggedAnd("Token for " + origins.firstUrl("/data") + ": ");
    }

    @Test
    public void aCrossOriginRedirectIsLoggedWithoutTheSecret() throws Exception {
        origins.first.enqueue(new MockResponse().setResponseCode(302)
                .setHeader("Location", origins.secondUrl("/landing")));
        origins.second.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request());
        assertEquals("control: substituted", SECRET, origins.take(origins.first).getRequestUrl()
                .queryParameter("key"));
        assertNotNull(origins.take(origins.second));
        assertNoValueLoggedAnd("Following redirect 302 to " + origins.secondUrl("/landing"));
    }

    @Test
    public void aSameOriginRedirectIsLoggedWithoutTheSecret() throws Exception {
        origins.first.enqueue(new MockResponse().setResponseCode(302)
                .setHeader("Location", origins.firstUrl("/next") + "?echo=" + SECRET));
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        origins.send(request());
        origins.take(origins.first);
        assertEquals("control: the hop was made", "/next?echo=" + SECRET, origins.take(origins.first).getPath());
        // the redirect target is logged without the query the server sent, which here echoes the secret
        assertNoValueLoggedAnd("Following redirect 302 to " + origins.firstUrl("/next"));
    }
}
