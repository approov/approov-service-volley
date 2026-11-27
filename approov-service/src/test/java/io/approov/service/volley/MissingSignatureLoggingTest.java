package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.util.Log;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A signature that cannot be produced is logged once per process at a visible level, and at debug level after
 * that, for each kind. The request is signed with the other signature, or goes unsigned, as before.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class MissingSignatureLoggingTest {
    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
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

    private void installMissing() {
        approov.when(() -> Approov.getInstallMessageSignature(ArgumentMatchers.anyString())).thenReturn("");
    }

    private void accountMissing() {
        approov.when(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString())).thenReturn("");
    }

    // signs a request carrying the token header with both signatures, returning the resulting headers
    private Map<String, String> sign() throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        return ApproovDefaultMessageSigning.combined().handleRequestProcessedHeaders(
                ApproovTestSupport.request("https://api.example.com/data"), headers, changes);
    }

    // the levels of the lines logged since the last call about the signature of the kind, then clears the log
    private static List<Integer> levels(String kind) {
        List<Integer> levels = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (item.msg.startsWith("Message signing:") && item.msg.contains(kind))
                levels.add(item.type);
        }
        ShadowLog.reset();
        return levels;
    }

    private static List<Integer> levels(Integer... expected) {
        List<Integer> list = new ArrayList<>();
        for (Integer level : expected)
            list.add(level);
        return list;
    }

    @Test
    public void aMissingInstallSignatureIsWarnedOnceThenDebug() throws Exception {
        installMissing();
        Map<String, String> signed = sign();
        assertTrue(signed.get("Signature"), signed.get("Signature").startsWith("account=:"));
        assertEquals(levels(Log.WARN), levels("install signature"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("install signature"));
    }

    @Test
    public void aMissingAccountSignatureIsWarnedOnceThenDebug() throws Exception {
        accountMissing();
        Map<String, String> signed = sign();
        assertTrue(signed.get("Signature"), signed.get("Signature").startsWith("install=:"));
        assertEquals(levels(Log.WARN), levels("account signature"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("account signature"));
    }

    @Test
    public void anUnavailableSignatureIsLoggedLikeAnEmptyOne() throws Exception {
        approov.when(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString()))
                .thenThrow(new IllegalStateException("no key"));
        Map<String, String> signed = sign();
        assertTrue(signed.get("Signature"), signed.get("Signature").startsWith("install=:"));
        assertEquals(levels(Log.WARN), levels("account signature"));
    }

    @Test
    public void whenBothAreMissingTheRequestIsUnsignedAndLoggedAsAnErrorOnceThenDebug() throws Exception {
        installMissing();
        accountMissing();
        Map<String, String> unsigned = sign();
        assertNull(unsigned.get("Signature"));
        assertNotNull(unsigned.get("Approov-Token"));
        assertEquals(levels(Log.ERROR), levels("no signature produced"));
        sign();
        assertEquals(levels(Log.DEBUG), levels("no signature produced"));
    }

    @Test
    public void theResetRestoresTheFirstTimeLogs() throws Exception {
        installMissing();
        sign();
        sign();
        ShadowLog.reset();
        ApproovDefaultMessageSigning.resetMissingSignatureLogsForTesting();
        sign();
        assertEquals(levels(Log.WARN), levels("install signature"));
    }
}
