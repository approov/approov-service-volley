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
import static org.junit.Assert.assertTrue;

import android.util.Log;

import com.android.volley.Header;
import com.android.volley.Request;
import com.android.volley.toolbox.HttpResponse;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The signed URL is the URL Android sends. Android's HttpURLConnection puts the request URL in the form of
 * OkHttp's HttpUrl before it writes the request line: a "|" in the path becomes %7C, a space %20, and a
 * character that is not ASCII its UTF-8 bytes percent-encoded, while a "|" in the query and an existing
 * escape stay as they are. The layer sends and signs that one form, for the first attempt and each redirect
 * hop. A URL that HttpUrl rejects is sent as written and unsigned, with one error log per process.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SignedWireUrlTest {
    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
        Approov.TokenFetchResult success =
                ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS, "jwt", "", "trace", false);
        approov.when(() -> Approov.fetchApproovTokenAndWait(ArgumentMatchers.anyString())).thenReturn(success);
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovService.reset();
        ApproovTestSupport.resetApproovServiceState();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        ShadowLog.reset();
    }

    // the device cases: the URL as the app wrote it, and the URL Android sends
    private static final String[][] DEVICE_CASES = {
            {"https://h/pipe|path?q=a|b", "https://h/pipe%7Cpath?q=a|b"},
            {"https://h/café?q=über✓", "https://h/caf%C3%A9?q=%C3%BCber%E2%9C%93"},
            {"https://h/a b?c d", "https://h/a%20b?c%20d"},
    };

    // URLs that are already in the form Android sends
    private static final String[] ENCODED = {
            "https://h/pc%25t?q=100%25",
            "https://h/a%20b?q=a%20b",
            "https://h/caf%C3%A9?q=caf%C3%A9",
            "https://h/s?f={%22a%22:1}&c=^`&p=x|y&plus=a+b",
    };

    // signs a request to the URL with the combined signer and gives the install signature base
    private String signatureBase(String url) throws Exception {
        approov.clearInvocations();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        Map<String, String> signed = ApproovDefaultMessageSigning.combined().handleRequestProcessedHeaders(
                ApproovTestSupport.request(Request.Method.GET, url, headers, null, null), headers, changes);
        assertNotNull("the request is signed: " + url, signed.get("Signature"));
        ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(base.capture()));
        return base.getValue();
    }

    private static String targetUriLine(String targetUri) {
        return "\"@target-uri\": " + targetUri + "\n";
    }

    private void assertSignedTargetUri(String expected, String url) throws Exception {
        String base = signatureBase(url);
        assertTrue("target URI " + expected + " for " + url + " in\n" + base, base.contains(targetUriLine(expected)));
    }

    @Test
    public void theSignedTargetUriIsTheFormAndroidSends() throws Exception {
        for (String[] pair : DEVICE_CASES)
            assertSignedTargetUri(pair[1], pair[0]);
    }

    @Test
    public void aUrlAlreadyInTheSentFormIsSignedUnchanged() throws Exception {
        for (String url : ENCODED)
            assertSignedTargetUri(url, url);
    }

    @Test
    public void normalisingTwiceIsTheIdentity() {
        List<String> urls = new ArrayList<>();
        for (String[] pair : DEVICE_CASES) {
            urls.add(pair[0]);
            urls.add(pair[1]);
        }
        Collections.addAll(urls, ENCODED);
        Collections.addAll(urls, "HTTPS://Host:443/p?#f", "https://[::1]:8443/a|b", "https://user:pw@h/p");
        for (String url : urls) {
            String once = ApproovRequestView.wireUrl(url);
            assertNotNull(url, once);
            assertEquals(url, once, ApproovRequestView.wireUrl(once));
        }
        for (String[] pair : DEVICE_CASES)
            assertEquals(pair[1], ApproovRequestView.wireUrl(pair[0]));
        for (String url : ENCODED)
            assertEquals(url, ApproovRequestView.wireUrl(url));
    }

    @Test
    public void anExplicitDefaultPortAndAFragmentAreNotSigned() throws Exception {
        assertSignedTargetUri("https://h/caf%C3%A9?q=a|b", "https://h:443/café?q=a|b#frag|ment");
        assertSignedTargetUri("http://h/pipe%7Cpath", "http://h:80/pipe|path#f");
        assertSignedTargetUri("https://h:8443/a%20b", "https://h:8443/a b#f");
    }

    /** A stack that sees what it would send and answers each attempt with the next response given. */
    private static final class RecordingStack extends ApproovHurlStack {
        final List<Request<?>> requests = new ArrayList<>();
        final List<Map<String, String>> headers = new ArrayList<>();
        final List<HttpResponse> responses = new ArrayList<>();

        @Override
        protected HttpResponse executeNetworkRequest(Request<?> request, Map<String, String> sent) {
            requests.add(request);
            headers.add(new LinkedHashMap<>(sent));
            return responses.isEmpty() ? new HttpResponse(200, Collections.<Header>emptyList())
                    : responses.remove(0);
        }
    }

    @Test
    public void theStackSendsTheUrlItSigns() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        for (String[] pair : DEVICE_CASES) {
            approov.clearInvocations();
            RecordingStack stack = new RecordingStack();
            stack.executeRequest(ApproovTestSupport.request(pair[0]), new LinkedHashMap<String, String>());
            assertEquals(1, stack.requests.size());
            // HurlStack opens the connection for the URL of the request it is given
            assertEquals(pair[0], pair[1], stack.requests.get(0).getUrl());
            assertNotNull(pair[0], stack.headers.get(0).get("Signature"));
            ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
            approov.verify(() -> Approov.getInstallMessageSignature(base.capture()));
            assertTrue(base.getValue(), base.getValue().contains(targetUriLine(pair[1])));
        }
    }

    @Test
    public void aRedirectHopIsSentAndSignedInTheFormAndroidSends() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        RecordingStack stack = new RecordingStack();
        stack.responses.add(new HttpResponse(302, Collections.singletonList(
                new Header("Location", "/hop|x/café?q=ü|v"))));
        stack.executeRequest(ApproovTestSupport.request("https://h/start"), new LinkedHashMap<String, String>());

        assertEquals(2, stack.requests.size());
        String hop = "https://h/hop%7Cx/caf%C3%A9?q=%C3%BC|v";
        assertEquals(hop, stack.requests.get(1).getUrl());
        assertNotNull(stack.headers.get(1).get("Signature"));
        ArgumentCaptor<String> bases = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(bases.capture()), Mockito.times(2));
        assertTrue(bases.getAllValues().get(1), bases.getAllValues().get(1).contains(targetUriLine(hop)));
        // the hop is classified and its token fetched for the URL that is sent
        approov.verify(() -> Approov.fetchApproovTokenAndWait(hop));
    }

    // the error lines logged for a URL that cannot be signed
    private static int urlErrors() {
        int n = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ((item.type == Log.ERROR) && item.msg.contains("URL"))
                n++;
        }
        return n;
    }

    @Test
    public void aUrlHttpUrlRejectsIsSentAsWrittenUnsignedWithOneErrorLog() throws Exception {
        ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
        String url = "https://example.com:99999/p|q";
        assertNull("HttpUrl rejects the port", okhttp3.HttpUrl.parse(url));
        for (int i = 0; i < 2; i++) {
            RecordingStack stack = new RecordingStack();
            stack.executeRequest(ApproovTestSupport.request(url), new LinkedHashMap<String, String>());
            assertEquals(1, stack.requests.size());
            assertEquals(url, stack.requests.get(0).getUrl());
            Map<String, String> sent = stack.headers.get(0);
            assertEquals("jwt", sent.get("Approov-Token"));
            assertNull(sent.get("Signature"));
            assertNull(sent.get("Signature-Input"));
        }
        approov.verify(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString()), Mockito.never());
        assertEquals("one error log for the process", 1, urlErrors());
    }
}
