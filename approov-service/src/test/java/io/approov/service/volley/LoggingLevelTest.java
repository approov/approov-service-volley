package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import android.util.Log;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * ApproovService.setLoggingLevel: ERROR writes errors, WARNING adds warnings, INFO (the default) adds
 * information and DEBUG adds debug lines, the loggable token of each request among them. OFF writes
 * nothing from the layer, errors included. The level is configuration, so initialize never resets it.
 * Debug logging enabled for the ApproovService tag (adb shell setprop log.tag.ApproovService DEBUG,
 * which ShadowLog.setLoggable stands in for) raises any level but OFF to DEBUG.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class LoggingLevelTest {
    private static final Set<String> LAYER_TAGS = new HashSet<>(Arrays.asList(
            "ApproovService", "ApproovHurlStack", "ApproovPinVerifier", "ApproovMsgSign"));

    // a distinctive line logged at each level
    private static final String ERROR_LINE = "getDeviceID: SDK not initialized";
    private static final String WARNING_LINE = "Pinning rejection for";
    private static final String INFO_LINE = "initialize: bypass mode";
    private static final String DEBUG_LINE = "setBindingHeader Probe-Binding";

    private static final String QUERY_VALUE = "query-value-never-logged";
    private static final String USER = "user-never-logged";

    @Before
    public void setUp() {
        ApproovService.reset();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        ApproovService.reset();
        ApproovTestSupport.resetApproovServiceState();
        ShadowLog.reset();
    }

    private static List<ShadowLog.LogItem> layerLogs() {
        List<ShadowLog.LogItem> items = new ArrayList<>();
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if (LAYER_TAGS.contains(item.tag))
                items.add(item);
        }
        return items;
    }

    private static boolean logged(int type, String text) {
        for (ShadowLog.LogItem item : layerLogs()) {
            if ((item.type == type) && (item.msg != null) && item.msg.contains(text))
                return true;
        }
        return false;
    }

    // causes a pin mismatch, which is logged as a warning
    private static void pinMismatch() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(Collections.singletonMap(
                    "api.example.com", Collections.singletonList(
                            java.util.Base64.getEncoder().encodeToString(
                                    MessageDigest.getInstance("SHA-256").digest(new byte[]{1})))));
            PublicKey publicKey = mock(PublicKey.class);
            when(publicKey.getEncoded()).thenReturn(new byte[]{2});
            X509Certificate certificate = mock(X509Certificate.class);
            when(certificate.getPublicKey()).thenReturn(publicKey);
            SSLSession session = mock(SSLSession.class);
            when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
            HostnameVerifier delegate = mock(HostnameVerifier.class);
            when(delegate.verify(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any()))
                    .thenReturn(true);
            assertFalse(new PinningHostnameVerifier(delegate).verify("api.example.com", session));
        }
    }

    // logs one line at each level: an error (a direct method before initialization), a warning (a pin
    // mismatch), a debug line, then an information line (bypass mode initialization)
    private void logOneLineAtEachLevel() throws Exception {
        assertThrows(ApproovException.class, ApproovService::getDeviceID);
        pinMismatch();
        ApproovService.setBindingHeader("Probe-Binding");
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
    }

    private void assertLevelsLogged(String what, boolean error, boolean warning, boolean info, boolean debug) {
        assertEquals(what + ": error", error, logged(Log.ERROR, ERROR_LINE));
        assertEquals(what + ": warning", warning, logged(Log.WARN, WARNING_LINE));
        assertEquals(what + ": info", info, logged(Log.INFO, INFO_LINE));
        assertEquals(what + ": debug", debug, logged(Log.DEBUG, DEBUG_LINE));
    }

    // sends a protected request whose URL carries a query, a fragment and user info, with debug logging
    // enabled for the ApproovService tag if asked, and returns the token lines logged for it
    private List<String> tokenLinesForAProtectedRequest(boolean debugTag) throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            String url = "https://" + USER + ":pw@api.example.com:8443/v1/items?q=" + QUERY_VALUE + "#frag";
            Approov.TokenFetchResult success = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS, "jwt-token", "", "", false);
            approov.when(() -> Approov.fetchApproovTokenAndWait(url)).thenReturn(success);
            ShadowLog.reset();
            if (debugTag)
                ShadowLog.setLoggable("ApproovService", Log.DEBUG);
            new ApproovHurlStack() {
                @Override
                protected com.android.volley.toolbox.HttpResponse executeNetworkRequest(
                        com.android.volley.Request<?> request, java.util.Map<String, String> headers) {
                    return mock(com.android.volley.toolbox.HttpResponse.class);
                }
            }.executeRequest(ApproovTestSupport.request(url), new LinkedHashMap<>());
            List<String> lines = new ArrayList<>();
            for (ShadowLog.LogItem item : layerLogs()) {
                assertFalse("the query is logged: " + item.msg, item.msg.contains(QUERY_VALUE));
                assertFalse("the user info is logged: " + item.msg, item.msg.contains(USER));
                assertFalse("the fragment is logged: " + item.msg, item.msg.contains("frag"));
                if (item.msg.startsWith("Token for "))
                    lines.add(item.msg);
            }
            return lines;
        }
    }

    @Test
    public void eachLevelLogsItsOwnLinesAndThoseOfTheLevelsBefore() throws Exception {
        for (ApproovLogLevel level : ApproovLogLevel.values()) {
            ApproovService.reset();
            ShadowLog.reset();
            ApproovService.setLoggingLevel(level);
            logOneLineAtEachLevel();
            int n = level.ordinal();
            assertLevelsLogged(level.name(), n >= 1, n >= 2, n >= 3, n >= 4);
        }
    }

    @Test
    public void theDefaultIsInfo() throws Exception {
        logOneLineAtEachLevel();
        assertLevelsLogged("default", true, true, true, false);
    }

    @Test
    public void offLogsNothingFromTheLayer() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        logOneLineAtEachLevel();
        assertEquals("layer lines at OFF: " + layerLogs().size(), 0, layerLogs().size());
    }

    @Test
    public void theDefaultDoesNotLogTheLoggableToken() throws Exception {
        assertEquals(new ArrayList<String>(), tokenLinesForAProtectedRequest(false));
    }

    @Test
    public void debugLogsTheLoggableTokenWithTheUrlWithoutItsQuery() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        List<String> lines = tokenLinesForAProtectedRequest(false);
        assertEquals("one token line: " + lines, 1, lines.size());
        assertTrue("host, port and path only: " + lines.get(0),
                lines.get(0).startsWith("Token for https://api.example.com:8443/v1/items: "));
    }

    @Test
    public void debugLoggingForTheTagEnablesDebugLinesAtAnyLevelButOff() throws Exception {
        for (ApproovLogLevel level : ApproovLogLevel.values()) {
            ApproovService.reset();
            ShadowLog.reset();
            ShadowLog.setLoggable("ApproovService", Log.DEBUG);
            ApproovService.setLoggingLevel(level);
            logOneLineAtEachLevel();
            boolean on = level != ApproovLogLevel.OFF;
            assertLevelsLogged(level.name() + " with the tag at debug", on, on, on, on);
        }
        // and the loggable token, at the default level
        ApproovService.reset();
        assertEquals(1, tokenLinesForAProtectedRequest(true).size());
    }

    @Test
    public void debugLoggingForTheTagDoesNotOverrideOff() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        assertEquals(new ArrayList<String>(), tokenLinesForAProtectedRequest(true));
        assertEquals("layer lines at OFF", 0, layerLogs().size());
    }

    @Test
    public void aLevelSetBeforeInitializeSurvivesIt() {
        // OFF before initialize: initialize logs nothing, and the lines after it neither
        ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        ApproovService.setBindingHeader("Probe-Binding");
        assertEquals("layer lines at OFF across initialize", 0, layerLogs().size());

        // DEBUG before initialize: debug lines still logged after it
        ApproovService.reset();
        ShadowLog.reset();
        ApproovService.setLoggingLevel(ApproovLogLevel.DEBUG);
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        ApproovService.setBindingHeader("Probe-Binding");
        assertTrue("debug after initialize", logged(Log.DEBUG, DEBUG_LINE));
    }

    @Test
    public void aNullLevelIsRejectedAndLeavesTheLevelUnchanged() throws Exception {
        ApproovService.setLoggingLevel(ApproovLogLevel.ERROR);
        assertThrows(IllegalArgumentException.class, () -> ApproovService.setLoggingLevel(null));
        logOneLineAtEachLevel();
        assertLevelsLogged("ERROR kept", true, false, false, false);
    }
}
