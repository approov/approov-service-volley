package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

/**
 * The decisions of the standard mutators on every token fetch status. CLOSE_FAILURE, whose decisions are
 * also the interface defaults, aborts on a failure other than NO_APPROOV_SERVICE and ALWAYS_PROCEED never
 * aborts. Under both, a secure string that cannot be obtained never aborts a request.
 */
public class StandardMutatorsTest {
    private static final String URL = "https://api.example.com/v1/items";

    private static final List<Approov.TokenFetchStatus> NETWORK_FAILURES = Arrays.asList(
            Approov.TokenFetchStatus.NO_NETWORK,
            Approov.TokenFetchStatus.POOR_NETWORK,
            Approov.TokenFetchStatus.MITM_DETECTED);

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
    }

    @After
    public void tearDown() {
        ApproovTestSupport.resetApproovServiceState();
    }

    private static Approov.TokenFetchResult result(Approov.TokenFetchStatus status) {
        return ApproovTestSupport.tokenResult(status);
    }

    // an anonymous mutator that inherits every default
    private static final ApproovServiceMutator INHERITING = new ApproovServiceMutator() {
    };

    @Test
    public void defaultIsCloseFailure() {
        assertSame(ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.DEFAULT);
        assertEquals("ApproovServiceMutator.CLOSE_FAILURE", ApproovServiceMutator.CLOSE_FAILURE.toString());
        assertEquals("ApproovServiceMutator.ALWAYS_PROCEED", ApproovServiceMutator.ALWAYS_PROCEED.toString());
    }

    @Test
    public void closeFailureProceedsOnSuccessAndNoApproovService() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(ApproovServiceMutator.CLOSE_FAILURE, INHERITING)) {
            assertTrue(mutator.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.SUCCESS), URL));
            assertTrue(mutator.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.NO_APPROOV_SERVICE), URL));
        }
    }

    @Test
    public void closeFailureSendsNoHeadersForUnknownAndUnprotectedUrls() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(ApproovServiceMutator.CLOSE_FAILURE, INHERITING)) {
            assertFalse(mutator.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.UNKNOWN_URL), URL));
            assertFalse(mutator.handleRequestFetchTokenResult(result(Approov.TokenFetchStatus.UNPROTECTED_URL), URL));
        }
    }

    @Test
    public void closeFailureThrowsTheNetworkExceptionForNetworkFailures() {
        for (Approov.TokenFetchStatus status : NETWORK_FAILURES) {
            ApproovNetworkException e = assertThrows(ApproovNetworkException.class, () ->
                    ApproovServiceMutator.CLOSE_FAILURE.handleRequestFetchTokenResult(result(status), URL));
            assertEquals(status, e.getTokenFetchStatus());
        }
    }

    @Test
    public void closeFailureProceedsOnANetworkFailureWhenTheStatusIsSent() throws Exception {
        ApproovService.setUseApproovStatusIfNoToken(true);
        for (Approov.TokenFetchStatus status : NETWORK_FAILURES)
            assertTrue(ApproovServiceMutator.CLOSE_FAILURE.handleRequestFetchTokenResult(result(status), URL));
    }

    @Test
    public void closeFailureThrowsTheFetchStatusExceptionForEveryOtherStatus() {
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            switch (status) {
                case SUCCESS:
                case NO_APPROOV_SERVICE:
                case UNKNOWN_URL:
                case UNPROTECTED_URL:
                case NO_NETWORK:
                case POOR_NETWORK:
                case MITM_DETECTED:
                    continue;
                default:
                    break;
            }
            ApproovFetchStatusException e = assertThrows("status " + status, ApproovFetchStatusException.class, () ->
                    ApproovServiceMutator.CLOSE_FAILURE.handleRequestFetchTokenResult(result(status), URL));
            assertEquals(status, e.getTokenFetchStatus());
            // REJECTED is reported as a fetch status failure like the rest, not a rejection
            assertFalse(status.name(), e instanceof ApproovNetworkException);
        }
    }

    @Test
    public void alwaysProceedNeverThrowsAndProceedsOnEveryStatusButUnknownAndUnprotected() throws Exception {
        ApproovServiceMutator mutator = ApproovServiceMutator.ALWAYS_PROCEED;
        for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
            boolean expected = status != Approov.TokenFetchStatus.UNKNOWN_URL
                    && status != Approov.TokenFetchStatus.UNPROTECTED_URL;
            assertEquals("status " + status, expected, mutator.handleRequestFetchTokenResult(result(status), URL));
        }
    }

    @Test
    public void substitutionDecisionsAreIdenticalAndNeverThrowInBothStandardMutators() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED, INHERITING)) {
            for (Approov.TokenFetchStatus status : Approov.TokenFetchStatus.values()) {
                boolean expected = status == Approov.TokenFetchStatus.SUCCESS;
                assertEquals(mutator + " header " + status, expected,
                        mutator.handleRequestHeaderSubstitutionResult(result(status), "X-Api-Key"));
                assertEquals(mutator + " query " + status, expected,
                        mutator.handleRequestQueryParamSubstitutionResult(result(status), "key"));
            }
        }
    }

    @Test
    public void shouldProcessIsTrueForARequestAndAbortsForNone() throws Exception {
        for (ApproovServiceMutator mutator : Arrays.asList(
                ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED)) {
            assertTrue(mutator.handleRequestShouldProcess(ApproovTestSupport.request(URL), null));
            assertThrows(ApproovException.class, () -> mutator.handleRequestShouldProcess(null, null));
        }
    }

    @Test
    public void thePrecheckAndDirectMethodDecisionsAreUnchanged() throws Exception {
        ApproovServiceMutator mutator = ApproovServiceMutator.CLOSE_FAILURE;
        assertThrows(ApproovRejectionException.class, () ->
                mutator.handlePrecheckResult(result(Approov.TokenFetchStatus.REJECTED)));
        assertThrows(ApproovNetworkException.class, () ->
                mutator.handleFetchTokenResult(result(Approov.TokenFetchStatus.NO_NETWORK)));
        mutator.handleFetchSecureStringResult(result(Approov.TokenFetchStatus.UNKNOWN_KEY), "lookup", "k");
    }
}
