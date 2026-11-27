package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import com.android.volley.Request;
import com.android.volley.toolbox.HttpResponse;
import com.criticalblue.approovsdk.Approov;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

public class ApproovHurlStackContractTest {

    private static final class RecordingHurlStack extends ApproovHurlStack {
        private Request<?> capturedRequest;
        private Map<String, String> capturedHeaders;

        @Override
        protected HttpResponse executeNetworkRequest(Request<?> request, Map<String, String> headers) {
            capturedRequest = request;
            capturedHeaders = headers == null ? null : new LinkedHashMap<>(headers);
            return mock(HttpResponse.class);
        }
    }

    private static final class RecordingMutator implements ApproovServiceMutator {
        private final boolean allowProceed;
        private final String extraHeaderValue;
        private final Approov.TokenFetchStatus forceFalseStatus;
        private ApproovRequestMutations capturedChanges;

        RecordingMutator(boolean allowProceed, String extraHeaderValue) {
            this(allowProceed, extraHeaderValue, null);
        }

        RecordingMutator(boolean allowProceed, String extraHeaderValue, Approov.TokenFetchStatus forceFalseStatus) {
            this.allowProceed = allowProceed;
            this.extraHeaderValue = extraHeaderValue;
            this.forceFalseStatus = forceFalseStatus;
        }

        @Override
        public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
                throws ApproovException {
            if (forceFalseStatus != null && approovResults.getStatus() == forceFalseStatus) {
                return false;
            }
            if (approovResults.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
                if (!allowProceed) {
                    throw new ApproovNetworkException("custom block");
                }
                return false;
            }
            return ApproovServiceMutator.super.handleRequestFetchTokenResult(approovResults, url);
        }

        @Override
        public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                ApproovRequestMutations changes) {
            capturedChanges = changes;
            if (extraHeaderValue == null) {
                return headers;
            }
            Map<String, String> mutated = new LinkedHashMap<>(headers);
            mutated.put("X-Mutated", extraHeaderValue);
            return mutated;
        }
    }

    // lists api.example.com as an Approov API domain, a key of the SDK pin set, so that a token fetch failure
    // for it is decided by the mutator rather than sent untouched
    private static void listApiHost(MockedStatic<Approov> approov) {
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(
                java.util.Collections.singletonMap("api.example.com", java.util.Collections.<String>emptyList()));
    }

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
    }

    @After
    public void tearDown() {
        ApproovService.setServiceMutator(ApproovServiceMutator.DEFAULT);
        ApproovTestSupport.resetApproovServiceState();
    }

    @Test
    public void hurlStackAddsApproovTokenTraceIdAndMutatorChangesOnSuccess() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setTokenHeader("Approov-Token", "Bearer ");
            RecordingMutator mutator = new RecordingMutator(true, "yes");
            ApproovService.setServiceMutator(mutator);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult successResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "jwt-token",
                    "",
                    "trace-123",
                    false);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(successResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            assertNotNull(stack.capturedRequest);
            assertEquals("Bearer jwt-token", stack.capturedHeaders.get("Approov-Token"));
            assertEquals("trace-123", stack.capturedHeaders.get("Approov-TraceID"));
            assertEquals("yes", stack.capturedHeaders.get("X-Mutated"));
            assertNotNull(mutator.capturedChanges);
            assertEquals("Approov-Token", mutator.capturedChanges.getTokenHeaderKey());
            assertEquals("Approov-TraceID", mutator.capturedChanges.getTraceIDHeaderKey());
            assertNull(mutator.capturedChanges.getAddedHeaderKeys());
        }
    }

    @Test
    public void hurlStackUsesFetchStatusAsTokenValueWhenConfigured() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setUseApproovStatusIfNoToken(true);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult mitmResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.MITM_DETECTED);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(mitmResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            assertEquals("MITM_DETECTED", stack.capturedHeaders.get("Approov-Token"));
            assertNull(stack.capturedHeaders.get("Approov-TraceID"));
        }
    }

    @Test
    public void hurlStackUsesFetchStatusWhenSdkReturnsEmptyTokenAndFallbackEnabled() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setUseApproovStatusIfNoToken(true);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult emptySuccessResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "",
                    "",
                    "",
                    false);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(emptySuccessResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            assertEquals("SUCCESS", stack.capturedHeaders.get("Approov-Token"));
        }
    }

    @Test
    public void hurlStackSendsNoApproovHeaderWhenMutatorReturnsFalseOnAFailure() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setUseApproovStatusIfNoToken(true);
            ApproovService.setServiceMutator(new RecordingMutator(
                    true,
                    null,
                    Approov.TokenFetchStatus.MITM_DETECTED));
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult mitmResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.MITM_DETECTED);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(mitmResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            // false on a failure status sends the request with no token or trace header
            assertFalse(stack.capturedHeaders.containsKey("Approov-Token"));
            assertFalse(stack.capturedHeaders.containsKey("Approov-TraceID"));
        }
    }

    @Test
    public void hurlStackSendsAnEmptyTokenHeaderOnNoApproovService() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult noServiceResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_APPROOV_SERVICE);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(noServiceResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            // NO_APPROOV_SERVICE proceeds with an empty token, and the empty trace ID is not sent
            assertEquals("", stack.capturedHeaders.get("Approov-Token"));
            assertFalse(stack.capturedHeaders.containsKey("Approov-TraceID"));
        }
    }

    @Test
    public void hurlStackUsesFallbackStatusHeaderForNoApproovServiceWhenConfigured() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setUseApproovStatusIfNoToken(true);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult noServiceResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_APPROOV_SERVICE);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(noServiceResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            assertEquals("NO_APPROOV_SERVICE", stack.capturedHeaders.get("Approov-Token"));
            assertFalse(stack.capturedHeaders.containsKey("Approov-TraceID"));
        }
    }

    @Test
    public void hurlStackCanDisableTraceIdHeaderEvenWhenTheSdkProvidesOne() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setTraceIDHeader(null);
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult successResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "jwt-token",
                    "",
                    "trace-123",
                    false);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(successResult);

            stack.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());

            assertEquals("jwt-token", stack.capturedHeaders.get("Approov-Token"));
            assertFalse(stack.capturedHeaders.containsKey("Approov-TraceID"));
        }
    }

    @Test
    public void customMutatorCanBlockNoApproovServiceRequests() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            listApiHost(approov);
            ApproovService.setServiceMutator(new RecordingMutator(false, null));
            RecordingHurlStack stack = new RecordingHurlStack();

            Approov.TokenFetchResult noServiceResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_APPROOV_SERVICE);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply"))
                    .thenReturn(noServiceResult);

            // the app's own exception is reported as a failure of the hook, with the original as its cause
            ApproovException error = assertThrows(
                    ApproovException.class,
                    () -> stack.executeRequest(
                            ApproovTestSupport.request("https://api.example.com/reply"),
                            new LinkedHashMap<>()));

            assertEquals(ApproovException.class, error.getClass());
            assertTrue(error.getMessage().startsWith("ApproovServiceMutator.handleRequestFetchTokenResult failed: "));
            assertTrue(error.getCause() instanceof ApproovNetworkException);
            assertEquals("custom block", error.getCause().getMessage());
            assertNull(stack.capturedRequest);
        }
    }
}
