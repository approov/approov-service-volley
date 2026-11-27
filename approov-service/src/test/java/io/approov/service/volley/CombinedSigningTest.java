package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The signer makes the decisions of another mutator: every decision hook calls the hook of that mutator, and
 * its processed headers hook calls the one of that mutator first and then signs the result. combined() signs
 * with both the install and the account signature.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class CombinedSigningTest {
    private static final String URL = "https://api.example.com/data";

    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovTestSupport.resetApproovServiceState();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
    }

    private static Approov.TokenFetchResult result(Approov.TokenFetchStatus status) {
        return ApproovTestSupport.tokenResult(status, "jwt", "", "trace", false);
    }

    // an app mutator that records every hook call with its arguments and decides the opposite of the interface
    // default for a SUCCESS result, so that a decision the signer made itself is told apart from its own
    static final class RecordingDecisions implements ApproovServiceMutator {
        final List<String> hooks = Collections.synchronizedList(new ArrayList<>());
        final List<Object[]> arguments = Collections.synchronizedList(new ArrayList<>());
        Map<String, String> processedResult = new LinkedHashMap<>(Collections.singletonMap("X-Decisions", "ran"));

        private void record(String hook, Object... args) {
            hooks.add(hook);
            arguments.add(args);
        }

        @Override
        public void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handlePrecheckResult", approovResults);
            throw new ApproovException("decided by handlePrecheckResult");
        }

        @Override
        public void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handleFetchTokenResult", approovResults);
            throw new ApproovException("decided by handleFetchTokenResult");
        }

        @Override
        public void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation,
                String key) throws ApproovException {
            record("handleFetchSecureStringResult", approovResults, operation, key);
            throw new ApproovException("decided by handleFetchSecureStringResult");
        }

        @Override
        public void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException {
            record("handleFetchCustomJWTResult", approovResults);
            throw new ApproovException("decided by handleFetchCustomJWTResult");
        }

        @Override
        public boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders) {
            record("handleRequestShouldProcess", request, additionalHeaders);
            return false;
        }

        @Override
        public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url) {
            record("handleRequestFetchTokenResult", approovResults, url);
            return false;
        }

        @Override
        public String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url) {
            record("handleRequestTokenHeaderValue", approovResults, url);
            return "decided";
        }

        @Override
        public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult approovResults,
                String header) {
            record("handleRequestHeaderSubstitutionResult", approovResults, header);
            return false;
        }

        @Override
        public boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult approovResults,
                String queryKey) {
            record("handleRequestQueryParamSubstitutionResult", approovResults, queryKey);
            return false;
        }

        @Override
        public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                ApproovRequestMutations changes) {
            record("handleRequestProcessedHeaders", request, headers, changes);
            return processedResult;
        }
    }

    interface ThrowingCall {
        void run() throws ApproovException;
    }

    private static void assertDecidedBy(String hook, ThrowingCall call) {
        try {
            call.run();
            fail(hook + ": the signer decided itself");
        } catch (ApproovException e) {
            assertEquals(hook, "decided by " + hook, e.getMessage());
        }
    }

    @Test
    public void everyHookOfTheMutatorInterfaceIsForwarded() throws Exception {
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        Request<?> request = ApproovTestSupport.request(URL);
        RecordingDecisions decisions = new RecordingDecisions();
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(decisions);
        Set<String> hooks = new TreeSet<>();
        for (Method hook : ApproovServiceMutator.class.getDeclaredMethods()) {
            if (!hook.isDefault())
                continue;
            hooks.add(hook.getName());
            Class<?>[] types = hook.getParameterTypes();
            Object[] args = new Object[types.length];
            for (int i = 0; i < types.length; i++) {
                if (types[i] == Request.class)
                    args[i] = request;
                else if (types[i] == Approov.TokenFetchResult.class)
                    args[i] = success;
                else if (types[i] == String.class)
                    args[i] = "argument-" + i;
                else if (types[i] == Map.class)
                    args[i] = new LinkedHashMap<String, String>();
                else if (types[i] == ApproovRequestMutations.class)
                    args[i] = new ApproovRequestMutations();
                else
                    fail(hook.getName() + ": a parameter type the test does not know: " + types[i]);
            }
            decisions.hooks.clear();
            decisions.arguments.clear();
            try {
                signer.getClass().getMethod(hook.getName(), types).invoke(signer, args);
            } catch (InvocationTargetException e) {
                assertTrue(hook.getName() + ": " + e.getCause(), e.getCause() instanceof ApproovException);
            }
            assertEquals(hook.getName() + " is forwarded", Collections.singletonList(hook.getName()),
                    decisions.hooks);
            assertTrue(hook.getName() + " passes its arguments", Arrays.equals(args, decisions.arguments.get(0)));
        }
        assertTrue("the hooks found: " + hooks, hooks.size() >= 10);
    }

    @Test
    public void eachDecisionHookIsTheDecisionsOwn() throws Exception {
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        Request<?> request = ApproovTestSupport.request(URL);
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(new RecordingDecisions());

        // the interface default on SUCCESS is true for each of these, or no exception
        assertFalse(signer.handleRequestShouldProcess(request, null));
        assertFalse(signer.handleRequestFetchTokenResult(success, URL));
        assertEquals("decided", signer.handleRequestTokenHeaderValue(success, URL));
        assertFalse(signer.handleRequestHeaderSubstitutionResult(success, "X-Api-Key"));
        assertFalse(signer.handleRequestQueryParamSubstitutionResult(success, "key"));
        assertDecidedBy("handlePrecheckResult", () -> signer.handlePrecheckResult(success));
        assertDecidedBy("handleFetchTokenResult", () -> signer.handleFetchTokenResult(success));
        assertDecidedBy("handleFetchSecureStringResult",
                () -> signer.handleFetchSecureStringResult(success, "lookup", "the-key"));
        assertDecidedBy("handleFetchCustomJWTResult", () -> signer.handleFetchCustomJWTResult(success));
    }

    @Test
    public void theProcessedHeadersHookOfTheDecisionsRunsFirstAndTheSignerSignsItsResult() throws Exception {
        Request<?> request = ApproovTestSupport.request(URL);
        ApproovRequestMutations changes = new ApproovRequestMutations();
        RecordingDecisions decisions = new RecordingDecisions();
        ApproovDefaultMessageSigning signer = new ApproovDefaultMessageSigning(decisions);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");

        // a request without a token header mutation is not signed, so the headers are the decisions' own
        assertSame(decisions.processedResult, signer.handleRequestProcessedHeaders(request, headers, changes));
        assertSame(request, decisions.arguments.get(0)[0]);
        assertSame(headers, decisions.arguments.get(0)[1]);

        // with a token header mutation and a factory the result of the decisions is what is signed
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        changes.setTokenHeaderKey("Approov-Token");
        decisions.processedResult = new LinkedHashMap<>();
        decisions.processedResult.put("Approov-Token", "changed");
        decisions.processedResult.put("X-Decisions", "ran");
        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, headers, changes);
        assertEquals("ran", signed.get("X-Decisions"));
        assertNotNull(signed.get("Signature"));
        assertEquals(Arrays.asList("handleRequestProcessedHeaders", "handleRequestProcessedHeaders"), decisions.hooks);
    }

    @Test
    public void aNullResultOfTheDecisionsPropagates() throws Exception {
        RecordingDecisions decisions = new RecordingDecisions();
        decisions.processedResult = null;
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        ApproovDefaultMessageSigning signer = ApproovDefaultMessageSigning.combined(decisions);
        assertNull(signer.handleRequestProcessedHeaders(ApproovTestSupport.request(URL), new LinkedHashMap<>(), changes));
    }

    @Test
    public void theNoArgumentSignerStillMakesCloseFailureDecisions() throws Exception {
        ApproovDefaultMessageSigning plain = new ApproovDefaultMessageSigning();
        Request<?> request = ApproovTestSupport.request(URL);
        Approov.TokenFetchResult success = result(Approov.TokenFetchStatus.SUCCESS);
        assertTrue(plain.handleRequestShouldProcess(request, null));
        assertTrue(plain.handleRequestFetchTokenResult(success, URL));
        assertTrue(plain.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.NO_APPROOV_SERVICE), URL));
        assertFalse(plain.handleRequestHeaderSubstitutionResult(result(Approov.TokenFetchStatus.REJECTED), "h"));
        plain.handlePrecheckResult(success);
        assertEquals("ApproovDefaultMessageSigning", plain.toString());
    }

    // the result of the token decision of the signer for a failed fetch, true if the request proceeds
    private static boolean proceedsOnNoNetwork(ApproovDefaultMessageSigning signer) {
        try {
            return signer.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.NO_NETWORK), URL);
        } catch (ApproovException e) {
            return false;
        }
    }

    @Test
    public void combinedMakesTheDecisionsGiven() {
        assertTrue(proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED)));
        assertFalse(proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined(ApproovServiceMutator.CLOSE_FAILURE)));
        assertFalse("the DEFAULT decisions", proceedsOnNoNetwork(ApproovDefaultMessageSigning.combined()));
    }

    @Test
    public void combinedDescribesItsDecisions() {
        assertEquals("ApproovDefaultMessageSigning(ApproovServiceMutator.ALWAYS_PROCEED)",
                ApproovDefaultMessageSigning.combined(ApproovServiceMutator.ALWAYS_PROCEED).toString());
    }

    @Test
    public void combinedRejectsNullDecisions() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ApproovDefaultMessageSigning.combined(null));
        assertTrue(e.getMessage(), e.getMessage().contains("decisions"));
    }

    @Test
    public void combinedReturnsANewSignerEachTime() {
        assertNotSame(ApproovDefaultMessageSigning.combined(), ApproovDefaultMessageSigning.combined());
    }

    @Test
    public void theConstructorThatTakesAMutatorIsNotPublic() {
        for (java.lang.reflect.Constructor<?> constructor : ApproovDefaultMessageSigning.class.getConstructors())
            assertEquals("only the no-argument constructor is public", 0, constructor.getParameterCount());
    }

    @Test
    public void combinedSignsWithBothTheInstallAndTheAccountSignature() throws Exception {
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        Map<String, String> signed = ApproovDefaultMessageSigning.combined().handleRequestProcessedHeaders(
                ApproovTestSupport.request(URL), headers, changes);

        String input = signed.get("Signature-Input");
        String signature = signed.get("Signature");
        assertNotNull(input);
        assertNotNull(signature);
        assertTrue(input, input.contains("install=(") && input.contains("account=("));
        assertTrue(signature, signature.contains("install=:") && signature.contains("account=:"));
        assertTrue(input, input.indexOf("install=(") < input.indexOf("account=("));
        assertTrue(input, input.contains("alg=\"ecdsa-p256-sha256\"") && input.contains("alg=\"hmac-sha256\""));
        assertTrue(changes.getAddedHeaderKeys().containsAll(Arrays.asList("Signature", "Signature-Input")));
    }
}
