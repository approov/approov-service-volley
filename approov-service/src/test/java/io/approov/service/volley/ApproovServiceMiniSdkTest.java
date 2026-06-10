package io.approov.service.volley;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import com.android.volley.Request;
import com.android.volley.toolbox.BaseHttpStack;
import com.android.volley.toolbox.HttpResponse;
import com.android.volley.toolbox.StringRequest;
import com.criticalblue.minisdk.testing.AttesterProxyController;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;

import com.criticalblue.approovsdk.Approov;

import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ApproovServiceMiniSdkTest {
    private final String validInitialConfig = "#cb-ivol#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=";
    private Context context;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
        AttesterProxyController.reset();
        ApproovService.initialize(context, validInitialConfig, "reinit-volley-tests");
    }

    @After
    public void tearDown() {
        ApproovService.setServiceMutator(ApproovServiceMutator.DEFAULT);
        AttesterProxyController.reset();
    }

    // ==================================================================================
    // SECTION 1: Initialization
    // TESTING_REQUIREMENTS.md §1
    // ==================================================================================

    @Test
    public void testInitializeIgnoresSameConfigAndRejectsDifferentConfig() {
        ApproovService.initialize(context, validInitialConfig);
        String differentConfig = "#cb-other#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=";
        try {
            ApproovService.initialize(context, differentConfig);
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assertNotNull(e.getMessage());
        }
        // Per TESTING_REQUIREMENTS §17-18: failure preserves the prior operating state.
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());
    }

    @Test
    public void testInitializeWithEmptyConfigBuildsPlainClient() throws Exception {
        reinitializeService(scenarioJson(uniqueCaseName("empty-config"),
            "\"protectedDomains\": [\"" + getTargetHost() + "\"]"));
        ApproovService.reset();
        ApproovService.initialize(context, "", "reinit-empty-config");

        assertTrue(ApproovService.isInitialized());
        assertFalse(ApproovService.isApproovEnabled());

        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        JSONObject reply = executeRequest(request);

        assertNull(getHeader(reply, "Approov-Token"));
        assertNull(getHeader(reply, "Approov-TraceID"));
    }

    @Test
    public void testInitializeWithEmptyConfigCanLaterEnableApproov() throws Exception {
        reinitializeService(scenarioJson(uniqueCaseName("empty-then-valid"),
            "\"protectedDomains\": [\"" + getTargetHost() + "\"]"));
        ApproovService.reset();
        ApproovService.initialize(context, "", "reinit-empty-config");

        assertTrue(ApproovService.isInitialized());
        assertFalse(ApproovService.isApproovEnabled());

        StringRequest request1 = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        JSONObject reply1 = executeRequest(request1);
        assertNull(getHeader(reply1, "Approov-Token"));
        assertNull(getHeader(reply1, "Approov-TraceID"));

        ApproovService.initialize(context, validInitialConfig);

        StringRequest request2 = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        JSONObject reply2 = executeRequest(request2);
        assertNotNull(getHeader(reply2, "Approov-Token"));
    }

    @Test
    public void testInitializeWithValidThenEmptyConfigIgnoresEmptyConfig() throws Exception {
        reinitializeService(scenarioJson(uniqueCaseName("valid-then-empty"),
            "\"protectedDomains\": [\"" + getTargetHost() + "\"]"));
        
        // Initialize with a valid config
        ApproovService.initialize(context, validInitialConfig);
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());

        // Reinitialize with an empty config (should be ignored)
        ApproovService.initialize(context, "", "reinit-empty-config");
        assertTrue(ApproovService.isInitialized());
        assertTrue(ApproovService.isApproovEnabled());

        // Verify that requests are still protected
        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        JSONObject reply = executeRequest(request);
        assertNotNull(getHeader(reply, "Approov-Token"));
    }

    // ==================================================================================
    // SECTION 2: Request Processing & Token Behaviors
    // TESTING_REQUIREMENTS.md §2
    // ==================================================================================

    @Test
    public void testGetDeviceIDReturnsMiniSDKDeviceID() throws ApproovException {
        assertEquals("daIvmEWBA2gvZny7a/RC/w==", ApproovService.getDeviceID());
    }

    @Test
    public void testUpdateRequestAddsTokenTraceBindingHashAndSubstitutions() throws Exception {
        String targetHost = getTargetHost();
        reinitializeService(scenarioJson(uniqueCaseName("substitutions"),
            "\"protectedDomains\": [\"" + targetHost + "\"]," +
            "\"initialSecureStrings\": {" +
            "  \"header-key\": \"header-secret\"," +
            "  \"query-key\": \"query-secret\"," +
            "  \"multiple-1\": \"secret-1\"," +
            "  \"multiple-2\": \"secret-2\"" +
            "}"
        ));

        ApproovService.setBindingHeader("Authorization");

        String baseUrl = getTargetURL() + "?api_key=query-key&p2=multiple-2";
        String url1 = ApproovService.substituteQueryParamInURLString(baseUrl, "api_key");
        String finalUrl = ApproovService.substituteQueryParamInURLString(url1, "p2");

        StringRequest request = new StringRequest(Request.Method.GET, finalUrl, null, null) {
            @Override
            public Map<String, String> getHeaders() {
                Map<String, String> hdrs = new HashMap<>();
                hdrs.put("Authorization", "Bearer oauth-token");
                hdrs.put("Api-Key", "header-key");
                hdrs.put("X-Multi-1", "pref-multiple-1");
                hdrs.put("X-Multi-2", "multiple-2");
                try {
                    ApproovService.substituteHeader(finalUrl, hdrs, "Api-Key", null);
                    ApproovService.substituteHeader(finalUrl, hdrs, "X-Multi-1", "pref-");
                    ApproovService.substituteHeader(finalUrl, hdrs, "X-Multi-2", null);
                } catch (io.approov.service.volley.ApproovException e) {
                    throw new RuntimeException(e);
                }
                return hdrs;
            }
        };

        JSONObject reply = executeRequest(request);
        String token = getHeader(reply, "Approov-Token");
        assertNotNull(token);
        assertNotNull(getHeader(reply, "Approov-TraceID"));
        assertEquals("header-secret", getHeader(reply, "Api-Key"));
        assertEquals("pref-secret-1", getHeader(reply, "X-Multi-1"));
        assertEquals("secret-2", getHeader(reply, "X-Multi-2"));

        String urlFromReply = reply.getString("url");
        assertTrue(urlFromReply.contains("api_key=query-secret"));
        assertTrue(urlFromReply.contains("p2=secret-2"));

        JSONObject payload = decodeJWTBody(token);
        assertEquals(sha256Base64("Bearer oauth-token"), payload.getString("pay"));
    }

    @Test
    public void testFetchTokenReturnsSignedTokenWithExpectedClaims() throws Exception {
        reinitializeServiceWithTargetHost("");
        String token = ApproovService.fetchToken(getTargetURL());
        JSONObject payload = decodeJWTBody(token);

        assertEquals("81.149.55.236", payload.getString("ip"));
        assertEquals("daIvmEWBA2gvZny7a/RC/w==", payload.getString("did"));
        assertEquals("j3AWy6", payload.getString("mskid"));
        assertEquals("IXPSB7TRK26LXE3M", payload.getString("arc"));
        assertTrue(payload.has("exp"));
    }

    @Test
    public void testUpdateRequestNoApproovServiceProceedsWithoutToken() throws Exception {
        reinitializeServiceWithTargetHost("");
        setDirective("{" +
            "  \"operation\": \"fetchApproovToken\"," +
            "  \"response\": {" +
            "    \"status\": \"NO_APPROOV_SERVICE\"" +
            "  }" +
            "}");

        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        JSONObject reply = executeRequest(request);

        assertNull(getHeader(reply, "Approov-Token"));
        assertNull(getHeader(reply, "Approov-TraceID"));
    }

    @Test
    public void testUpdateRequestCanIgnoreExcludedURL() throws Exception {
        reinitializeServiceWithTargetHost("");
        ApproovService.addExclusionURLRegex("^.*excluded.*$");

        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL() + "/excluded", null, null);
        JSONObject reply = executeRequest(request);

        String token = getHeader(reply, "Approov-Token");
        assertNull("Expected null Approov-Token for excluded URL, but got: " + token, token);
    }

    @Test
    public void testUpdateRequestToUnprotectedUrlIsUnmodified() throws Exception {
        // Purposely reinitialize cleanly using a target that specifically excludes our explicit unprotected endpoint
        // This ensures the local SDK routing treats it organically as an UNPROTECTED_URL.
        reinitializeServiceWithTargetHost(""); 

        String baseUrl = getUnprotectedURL() + "?api_key=query-key";
        String finalUrl = ApproovService.substituteQueryParamInURLString(baseUrl, "api_key");

        StringRequest request = new StringRequest(Request.Method.GET, finalUrl, null, null) {
            @Override
            public Map<String, String> getHeaders() {
                Map<String, String> hdrs = new HashMap<>();
                hdrs.put("Api-Key", "header-key");
                try {
                    ApproovService.substituteHeader(finalUrl, hdrs, "Api-Key", null);
                } catch (io.approov.service.volley.ApproovException e) {
                    throw new RuntimeException(e);
                }
                return hdrs;
            }

            @Override
            protected Map<String, String> getParams() {
                Map<String, String> params = new HashMap<>();
                params.put("form_key", "form-secret");
                try {
                    ApproovService.substituteQueryParam(finalUrl, params, "form_key");
                } catch (io.approov.service.volley.ApproovException e) {
                    throw new RuntimeException(e);
                }
                return params;
            }
        };

        JSONObject reply = executeRequest(request);

        assertNull("UNPROTECTED request should not emit Approov Tokens natively!", getHeader(reply, "Approov-Token"));
        assertEquals("Substitutions must bypass completely without modifying value", "header-key", getHeader(reply, "Api-Key"));

        String urlFromReply = reply.getString("url");
        assertTrue("Substitutions to URL query params must skip execution identically", urlFromReply.contains("api_key=query-key"));
    }

    @Test
    public void testFetchTokenThrowsNetworkingErrorForNoNetwork() throws Exception {
        reinitializeServiceWithTargetHost("");
        setDirective("{" +
            "  \"operation\": \"fetchApproovToken\"," +
            "  \"response\": {" +
            "    \"status\": \"NO_NETWORK\"" +
            "  }" +
            "}");

        try {
            ApproovService.fetchToken(getTargetURL());
            fail("Expected ApproovNetworkException");
        } catch (ApproovNetworkException e) {
            assertTrue(e.getMessage().contains("fetchToken: NO_NETWORK"));
        }
    }

    @Test
    public void testFetchTokenThrowsNetworkExceptionForMitmDetected() throws Exception {
        reinitializeServiceWithTargetHost("");
        setDirective("{" +
            "  \"operation\": \"fetchApproovToken\"," +
            "  \"response\": {" +
            "    \"status\": \"MITM_DETECTED\"" +
            "  }" +
            "}");

        try {
            ApproovService.fetchToken(getTargetURL());
            fail("Expected ApproovNetworkException");
        } catch (ApproovNetworkException e) {
            assertTrue(e.getMessage().contains("fetchToken: MITM_DETECTED"));
        }
    }

    // ==================================================================================
    // SECTION 3: Custom Mutators
    // TESTING_REQUIREMENTS.md §3
    // ==================================================================================

    @Test
    public void testCustomMutatorCanChangeSubstitutedHeaderValue() throws Exception {
        String targetHost = getTargetHost();
        reinitializeService(scenarioJson(uniqueCaseName("mutator-subst"),
            "\"protectedDomains\": [\"" + targetHost + "\"]," +
            "\"initialSecureStrings\": {" +
            "  \"header-key\": \"secret-value\"" +
            "}"
        ));

        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult result, String header) throws ApproovException {
                return ApproovServiceMutator.super.handleRequestHeaderSubstitutionResult(result, header);
            }
            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> r, Map<String, String> h, ApproovRequestMutations c) throws ApproovException {
                Map<String, String> mutated = new HashMap<>(h);
                mutated.put("X-Mutated", "yes");
                return mutated;
            }
        });

        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL(), null, null) {
            @Override
            public Map<String, String> getHeaders() {
                Map<String, String> hdrs = new HashMap<>();
                hdrs.put("Api-Key", "header-key");
                try {
                    ApproovService.substituteHeader(this.getUrl(), hdrs, "Api-Key", null);
                } catch (io.approov.service.volley.ApproovException e) {
                    throw new RuntimeException(e);
                }
                return hdrs;
            }
        };

        JSONObject reply = executeRequest(request);
        assertEquals("yes", getHeader(reply, "X-Mutated"));
        assertEquals("secret-value", getHeader(reply, "Api-Key"));
    }

    @Test
    public void testCustomMutatorCanBlockRequestOnNoApproovService() throws Exception {
        reinitializeServiceWithTargetHost("");
        ApproovService.setServiceMutator(new ApproovServiceMutator() {
            @Override
            public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult result, String url) throws ApproovException {
                if (result.getStatus() == Approov.TokenFetchStatus.NO_APPROOV_SERVICE) {
                    throw new ApproovNetworkException(result.getStatus(), "custom block");
                }
                return ApproovServiceMutator.super.handleRequestFetchTokenResult(result, url);
            }
        });

        setDirective("{" +
            "  \"operation\": \"fetchApproovToken\"," +
            "  \"response\": {" +
            "    \"status\": \"NO_APPROOV_SERVICE\"" +
            "  }" +
            "}");

        StringRequest request = new StringRequest(Request.Method.GET, getTargetURL(), null, null);
        try {
            executeRequest(request);
            fail("Expected network exception");
        } catch (ApproovException e) {
            assertTrue(e.getMessage().contains("custom block"));
        }
    }

    // ==================================================================================
    // SECTION 4: Pinning
    // TESTING_REQUIREMENTS.md §4
    // ==================================================================================

    @Test
    public void testCreateConnectionAttachesPinningHostnameVerifier() throws Exception {
        String targetHost = getTargetHost();
        reinitializeService(scenarioJson(uniqueCaseName("pin-mismatch"),
            "\"protectedDomains\": [\"" + targetHost + "\"]," +
            "\"pins\": {" +
            "  \"public-key-sha256\": {" +
            "    \"" + targetHost + "\": [\"INVALID_PIN_ABCDEF1234567890=\"]" +
            "  }" +
            "}"
        ));

        // Robolectric bypasses HostnameVerifier for real requests so this only checks that
        // PinningHostnameVerifier is attached by ApproovHurlStack; the verifier's pin
        // accept/reject behavior is covered by PinningHostnameVerifierContractTest.
        java.net.URL url = new java.net.URL(getTargetURL());
        com.android.volley.toolbox.BaseHttpStack stack = ApproovService.getBaseHttpStack();
        // In Volley 1.2+, createConnection is protected, so we reflect.
        java.lang.reflect.Method m = stack.getClass().getSuperclass().getDeclaredMethod("createConnection", java.net.URL.class);
        m.setAccessible(true);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) m.invoke(stack, url);

        assertTrue(conn instanceof javax.net.ssl.HttpsURLConnection);
        javax.net.ssl.HttpsURLConnection httpsConn = (javax.net.ssl.HttpsURLConnection) conn;

        assertNotNull(httpsConn.getHostnameVerifier());
        assertEquals("PinningHostnameVerifier", httpsConn.getHostnameVerifier().getClass().getSimpleName());
    }

    // ==================================================================================
    // SECTION 5: Message Signing
    // TESTING_REQUIREMENTS.md §5
    // ==================================================================================

    @Test
    public void testGetMessageSignatureReturnsToken() throws Exception {
        reinitializeServiceWithTargetHost("");
        String sig = ApproovService.getMessageSignature("my-message");
        assertNotNull(sig);
        assertTrue(sig.length() > 20);
    }

    // ==================================================================================
    // SECTION 6: Secure Strings & Custom JWT
    // TESTING_REQUIREMENTS.md §6
    // ==================================================================================

    @Test
    public void testFetchSecureStringReturnsValueOnSuccess() throws Exception {
        reinitializeService(scenarioJson(uniqueCaseName("secure-string-success"),
            "\"protectedDomains\": [\"" + getTargetHost() + "\"]," +
            "\"initialSecureStrings\": {" +
            "  \"my-secret-key\": \"my-secret-value\"" +
            "}"
        ));
        String result = ApproovService.fetchSecureString("my-secret-key", null);
        assertEquals("my-secret-value", result);
    }

    @Test
    public void testFetchSecureStringReturnsNullForUnknownKey() throws Exception {
        reinitializeServiceWithTargetHost("");
        String result = ApproovService.fetchSecureString("non-existent-key", null);
        assertNull(result);
    }

    @Test
    public void testFetchCustomJWTReturnsTokenOnSuccess() throws Exception {
        reinitializeServiceWithTargetHost("");
        String jwt = ApproovService.fetchCustomJWT("{\"custom\":\"payload\"}");
        JSONObject payload = decodeJWTBody(jwt);
        assertEquals("payload", payload.getString("custom"));
    }

    @Test
    public void testFetchCustomJWTThrowsExceptionOnMitm() throws Exception {
        reinitializeServiceWithTargetHost("");
        setDirective("{" +
            "  \"operation\": \"fetchCustomJWT\"," +
            "  \"response\": {" +
            "    \"status\": \"MITM_DETECTED\"" +
            "  }" +
            "}");

        try {
            ApproovService.fetchCustomJWT("{\"custom\":\"payload\"}");
            fail("Expected network exception");
        } catch (ApproovNetworkException e) {
            assertTrue(e.getMessage().contains("fetchCustomJWT: MITM_DETECTED"));
        }
    }

    // ==================================================================================
    // Test Helpers
    // ==================================================================================

    private String getTargetURL() {
        String url = System.getenv("TESTING_REPLY_URL");
        return (url != null) ? url : "https://replay.ivol.workers.dev";
    }

    private String getUnprotectedURL() {
        String url = System.getenv("TESTING_REPLY_URL_UNPROTECTED");
        return (url != null) ? url : "https://replay-unprotected.ivol.workers.dev";
    }

    private String getTargetHost() {
        String url = getTargetURL();
        return url.replace("https://", "").split("/")[0];
    }

    private void reinitializeServiceWithTargetHost(String scenarioBody) throws Exception {
        String targetHost = getTargetHost();
        String domainsJson = "\"protectedDomains\": [\"" + targetHost + "\"]," +
                             "\"pins\": {\"public-key-sha256\": {\"" + targetHost + "\": []}}";
        String fullBody = scenarioBody.isEmpty() ? domainsJson : domainsJson + ", " + scenarioBody;

        reinitializeService(scenarioJson(uniqueCaseName("target-host"), fullBody));
    }

    private void reinitializeService(String scenarioJson) {
        AttesterProxyController.reset();
        if (scenarioJson != null) {
            AttesterProxyController.loadScenarioJson(scenarioJson);
        }
        ApproovService.initialize(context, validInitialConfig, "reinit");
    }

    private void setDirective(String json) {
        AttesterProxyController.setNextAttestationDirectiveJson(json);
    }

    private String uniqueCaseName(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().toLowerCase();
    }

    private String scenarioJson(String caseName, String body) {
        return "{" +
            "  \"activeCase\": \"" + caseName + "\"," +
            "  \"cases\": {" +
            "    \"" + caseName + "\": {" +
            "      " + body + "" +
            "    }" +
            "  }" +
            "}";
    }

    private JSONObject executeRequest(Request<?> request) throws Exception {
        BaseHttpStack stack = ApproovService.getBaseHttpStack();
        if (stack == null) {
            stack = new com.android.volley.toolbox.HurlStack();
        }
        HttpResponse response = stack.executeRequest(request, Collections.emptyMap());
        InputStream in = response.getContent();
        if (in == null) return new JSONObject();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return new JSONObject(sb.toString());
    }

    private String getHeader(JSONObject reply, String key) throws Exception {
        if (!reply.has("headers")) return null;
        JSONObject headers = reply.getJSONObject("headers");
        String lowerKey = key.toLowerCase();
        if (headers.has(lowerKey)) {
            Object val = headers.get(lowerKey);
            if (val instanceof String) return (String) val;
            if (val instanceof org.json.JSONArray) {
                org.json.JSONArray arr = (org.json.JSONArray) val;
                if (arr.length() > 0) return arr.getString(0);
            }
        }
        if (headers.has(key)) {
            Object val = headers.get(key);
            if (val instanceof String) return (String) val;
            if (val instanceof org.json.JSONArray) {
                org.json.JSONArray arr = (org.json.JSONArray) val;
                if (arr.length() > 0) return arr.getString(0);
            }
        }
        return null;
    }

    private JSONObject decodeJWTBody(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return null;
        byte[] bytes = Base64.getUrlDecoder().decode(parts[1]);
        return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
    }

    private String sha256Base64(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }
}
