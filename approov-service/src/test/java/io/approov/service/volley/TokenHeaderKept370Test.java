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
import org.robolectric.shadows.ShadowLog;

import java.util.LinkedHashMap;
import java.util.Map;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The token and trace headers are set by the layer, so a processed headers hook that returns a map without them,
 * or with another value, does not change what is sent: the layer puts its headers back, signs with them, and
 * logs a warning once per process. A header the hook adds is kept.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class TokenHeaderKept370Test {
    private static final String WARNING = "handleRequestProcessedHeaders: removed or changed the Approov token header, restored";
    private static final String TRACE_WARNING = "handleRequestProcessedHeaders: removed or changed the Approov trace header, restored";

    private MiniSdkHttpsOrigins origins;

    // what a hook does to the headers it is given
    private interface Hook {
        Map<String, String> apply(Map<String, String> headers);
    }

    private static ApproovServiceMutator mutator(Hook hook) {
        return new ApproovServiceMutator() {
            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> request,
                    Map<String, String> headers, ApproovRequestMutations changes) {
                return hook.apply(headers);
            }
        };
    }

    // a hook that returns only the header it adds
    private static Map<String, String> onlyApp() {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("X-App", "added");
        return result;
    }

    @Before
    public void setUp() throws Exception {
        origins = new MiniSdkHttpsOrigins(true);
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        ShadowLog.reset();
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
        ShadowLog.reset();
    }

    private RecordedRequest deliver() throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        assertEquals(200, origins.send(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/h"))).getStatusCode());
        return origins.take(origins.first);
    }

    private static int warnings(String text) {
        int n = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (item.msg.contains(text))
                n++;
        }
        return n;
    }

    @Test
    public void droppedTokenIsRestoredAndWarnedOnce() throws Exception {
        ApproovService.setServiceMutator(mutator(headers -> onlyApp()));
        for (int i = 0; i < 2; i++) {
            RecordedRequest recorded = deliver();
            assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
            assertEquals("trace-1", recorded.getHeader("Approov-TraceID"));
            assertEquals("added", recorded.getHeader("X-App"));
        }
        assertEquals(1, warnings(WARNING));
        assertEquals(1, warnings(TRACE_WARNING));
    }

    @Test
    public void changedTokenIsRestoredAndWarnedOnce() throws Exception {
        ApproovService.setServiceMutator(mutator(headers -> {
            Map<String, String> result = new LinkedHashMap<>(headers);
            result.put("Approov-Token", "forged");
            return result;
        }));
        for (int i = 0; i < 2; i++)
            assertEquals("jwt-token", deliver().getHeader("Approov-Token"));
        assertEquals(1, warnings(WARNING));
    }

    @Test
    public void aHookThatOnlyAddsAHeaderCausesNoWarning() throws Exception {
        ApproovService.setServiceMutator(mutator(headers -> {
            Map<String, String> result = new LinkedHashMap<>(headers);
            result.put("X-App", "added");
            return result;
        }));
        RecordedRequest recorded = deliver();
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        assertEquals("added", recorded.getHeader("X-App"));
        assertEquals(0, warnings("restored"));
    }

    @Test
    public void signatureCoversTheRestoredTokenWhenTheHookDropsIt() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(mutator(headers -> onlyApp())));
        RecordedRequest recorded = deliver();
        assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
        String input = recorded.getHeader("Signature-Input");
        assertNotNull(input);
        assertTrue(input, input.toLowerCase().contains("\"approov-token\""));
        assertEquals(1, warnings(WARNING));
    }

    @Test
    public void signatureCoversTheRestoredTokenWhenTheHookChangesIt() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined(mutator(headers -> {
            Map<String, String> result = new LinkedHashMap<>(headers);
            result.put("Approov-Token", "forged");
            return result;
        })));
        for (int i = 0; i < 2; i++) {
            RecordedRequest recorded = deliver();
            assertEquals("jwt-token", recorded.getHeader("Approov-Token"));
            assertTrue(recorded.getHeader("Signature-Input").toLowerCase().contains("\"approov-token\""));
        }
        assertEquals(1, warnings(WARNING));
    }
}
