package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.util.Log;

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
import org.robolectric.shadows.ShadowLog;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Message signatures take their created and expires times from the SDK's server adjusted time while
 * protection is enabled, so that a device whose clock is wrong still signs within the backend's window. If
 * the SDK call fails the signature is still produced, on the device clock, with a warning.
 * ApproovService.getServerAdjustedCurrentTimeMS() returns the SDK value and, like the other direct methods,
 * fails before protection is enabled. The server time is three hours apart from the device clock, so a
 * signature stamped from the device clock cannot pass for one stamped from the server time.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ServerAdjustedTimeTest {
    private static final long OFFSET_MS = TimeUnit.HOURS.toMillis(3);
    private static final long DEFAULT_EXPIRES_LIFETIME = 15;
    private static final Pattern CREATED = Pattern.compile(";created=(\\d+)");
    private static final Pattern EXPIRES = Pattern.compile(";expires=(\\d+)");

    // a signer that returns fixed signatures, so that no SDK key is needed
    private static final class FixedSigner extends ApproovDefaultMessageSigning {
        @Override
        protected String getInstallMessageSignature(String message) {
            // a canonical DER encoding of r=1 and s=2
            return Base64.getEncoder().encodeToString(new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
        }

        @Override
        protected byte[] decodeBase64(String base64) {
            return Base64.getDecoder().decode(base64);
        }
    }

    private MockedStatic<Approov> approov;
    private long lastServerTime;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        approov.when(Approov::getServerAdjustedCurrentTimeMS).thenAnswer(invocation -> {
            lastServerTime = System.currentTimeMillis() - OFFSET_MS;
            return lastServerTime;
        });
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovTestSupport.resetApproovServiceState();
        ShadowLog.reset();
    }

    // signs a request and returns the Signature-Input it carries
    private String signatureInput() throws Exception {
        FixedSigner signer = new FixedSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "jwt-token");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        Request<?> request = ApproovTestSupport.request(Request.Method.GET,
                "https://api.example.com/signed", headers, null, null);
        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, headers, changes);
        String input = signed.get("Signature-Input");
        assertNotNull("the request is signed", input);
        return input;
    }

    private static long parameter(Pattern pattern, String input) {
        Matcher matcher = pattern.matcher(input);
        assertTrue("no " + pattern + " in " + input, matcher.find());
        return Long.parseLong(matcher.group(1));
    }

    private static int warningsContaining(String text) {
        int count = 0;
        for (ShadowLog.LogItem item : ShadowLog.getLogs()) {
            if ((item.type == Log.WARN) && item.msg.contains(text))
                count++;
        }
        return count;
    }

    @Test
    public void createdAndExpiresFollowTheServerAdjustedTime() throws Exception {
        String input = signatureInput();

        long created = parameter(CREATED, input);
        assertEquals("created is the server adjusted time, not the device clock", lastServerTime / 1000, created);
        assertEquals(created + DEFAULT_EXPIRES_LIFETIME, parameter(EXPIRES, input));
    }

    @Test
    public void aFailingServerTimeFallsBackToTheDeviceClockWithOneWarning() throws Exception {
        approov.when(Approov::getServerAdjustedCurrentTimeMS).thenThrow(new IllegalStateException("server time failure"));
        long before = System.currentTimeMillis() / 1000;
        String input = signatureInput();
        long after = System.currentTimeMillis() / 1000;

        long created = parameter(CREATED, input);
        assertTrue("created is the device clock: " + created, (created >= before) && (created <= after));
        assertEquals(created + DEFAULT_EXPIRES_LIFETIME, parameter(EXPIRES, input));
        assertEquals("one warning for the one signature", 1, warningsContaining("server adjusted time unavailable"));
    }

    @Test
    public void anSdkWithoutTheMethodFallsBackToTheDeviceClockWithOneWarning() throws Exception {
        // an app that forces an older Approov SDK at runtime has no getServerAdjustedCurrentTimeMS
        approov.when(Approov::getServerAdjustedCurrentTimeMS)
                .thenThrow(new NoSuchMethodError("getServerAdjustedCurrentTimeMS"));
        long before = System.currentTimeMillis() / 1000;
        String input = signatureInput();
        long after = System.currentTimeMillis() / 1000;

        long created = parameter(CREATED, input);
        assertTrue("created is the device clock: " + created, (created >= before) && (created <= after));
        assertEquals("one warning for the one signature", 1, warningsContaining("server adjusted time unavailable"));
    }

    @Test
    public void inBypassModeTheDeviceClockIsUsedWithoutAWarning() throws Exception {
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        // an installed signer is reset by initialize, but a signer built by the app signs in any mode
        ApproovTestSupport.resetApproovServiceState();
        long before = System.currentTimeMillis() / 1000;
        String input = signatureInput();
        long after = System.currentTimeMillis() / 1000;

        long created = parameter(CREATED, input);
        assertTrue("created is the device clock: " + created, (created >= before) && (created <= after));
        assertEquals(0, warningsContaining("server adjusted time unavailable"));
        approov.verify(Approov::getServerAdjustedCurrentTimeMS, Mockito.never());
    }

    @Test
    public void theDirectMethodReturnsTheSdkValue() throws Exception {
        long value = ApproovService.getServerAdjustedCurrentTimeMS();
        assertEquals(lastServerTime, value);
    }

    @Test
    public void theDirectMethodWrapsAnSdkFailure() {
        IllegalStateException cause = new IllegalStateException("server time failure");
        approov.when(Approov::getServerAdjustedCurrentTimeMS).thenThrow(cause);

        ApproovException e = assertThrows(ApproovException.class, ApproovService::getServerAdjustedCurrentTimeMS);
        assertSame(cause, e.getCause());
    }

    @Test
    public void theDirectMethodWrapsAnSdkWithoutTheMethod() {
        NoSuchMethodError missing = new NoSuchMethodError("getServerAdjustedCurrentTimeMS");
        approov.when(Approov::getServerAdjustedCurrentTimeMS).thenThrow(missing);

        ApproovException e = assertThrows(ApproovException.class, ApproovService::getServerAdjustedCurrentTimeMS);
        assertSame(missing, e.getCause().getCause());
    }

    @Test
    public void theDirectMethodFailsBeforeProtectionIsEnabled() {
        ApproovTestSupport.resetApproovServiceState();
        ApproovException e = assertThrows(ApproovException.class, ApproovService::getServerAdjustedCurrentTimeMS);
        assertTrue(e.getMessage(), e.getMessage().contains("not initialized"));
        ApproovService.initialize(ApproovTestSupport.mockContext(), "");
        assertThrows(ApproovException.class, ApproovService::getServerAdjustedCurrentTimeMS);
    }
}
