package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mockStatic;

import android.content.Context;

import com.android.volley.toolbox.BaseHttpStack;
import com.criticalblue.approovsdk.Approov;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

public class ApproovServiceContractTest {

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
    }

    @After
    public void tearDown() {
        ApproovTestSupport.resetApproovServiceState();
    }

    @Test
    public void initializeRestoresDefaultHeadersTraceIdAndFallbackConfiguration() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            assertNull(ApproovService.getBaseHttpStack());

            ApproovTestSupport.initializeApproovService(approov);
            BaseHttpStack baseHttpStack = ApproovService.getBaseHttpStack();

            assertEquals("Approov-Token", ApproovTestSupport.getStaticField("approovTokenHeader", String.class));
            assertEquals("", ApproovTestSupport.getStaticField("approovTokenPrefix", String.class));
            assertEquals("Approov-TraceID", ApproovTestSupport.getStaticField("approovTraceIDHeader", String.class));
            assertFalse(ApproovService.getUseApproovStatusIfNoToken());
            assertNotNull(baseHttpStack);
            assertTrue(baseHttpStack instanceof ApproovHurlStack);

            ApproovService.setApproovTraceIDHeader(null);
            ApproovService.setUseApproovStatusIfNoToken(true);

            assertNull(ApproovTestSupport.getStaticField("approovTraceIDHeader", String.class));
            assertTrue(ApproovService.getUseApproovStatusIfNoToken());
            approov.verify(() -> Approov.setUserProperty("approov-service-volley"));
        }
    }

    @Test
    public void initializeIgnoresDuplicateCallsWithSameConfig() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            Context context = ApproovTestSupport.mockContext();

            ApproovService.initialize(context, "config-a");
            BaseHttpStack firstStack = ApproovService.getBaseHttpStack();
            ApproovService.initialize(context, "config-a");

            assertNotNull(firstStack);
            assertEquals(firstStack, ApproovService.getBaseHttpStack());
            approov.verify(() -> Approov.initialize(context, "config-a", "auto", ""));
        }
    }

    @Test
    public void initializeThrowsForDifferentConfigAfterSuccess() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            Context context = ApproovTestSupport.mockContext();

            ApproovService.initialize(context, "config-a");
            IllegalStateException error = assertThrows(
                    IllegalStateException.class,
                    () -> ApproovService.initialize(context, "config-b"));

            assertEquals("ApproovService layer is already initialized", error.getMessage());
            approov.verify(() -> Approov.initialize(context, "config-a", "auto", ""));
        }
    }

    @Test
    public void initializeAllowsReinitCommentWhenNativeSdkIsAlreadyInitialized() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            Context context = ApproovTestSupport.mockContext();
            approov.when(() -> Approov.initialize(context, "config-a", "auto", "reinit-tests"))
                    .thenThrow(new IllegalStateException("already initialized"));

            ApproovService.initialize(context, "config-a", "reinit-tests");

            assertNotNull(ApproovService.getBaseHttpStack());
            assertTrue(ApproovTestSupport.getStaticField("isInitialized", Boolean.class));
            assertEquals("config-a", ApproovTestSupport.getStaticField("configString", String.class));
            approov.verify(() -> Approov.setUserProperty("approov-service-volley"));
        }
    }

    @Test
    public void initializeFailureClearsApproovStackAndLeavesPlainVolleyFallback() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            Context context = ApproovTestSupport.mockContext();
            ApproovService.initialize(context, "config-a");
            assertNotNull(ApproovService.getBaseHttpStack());

            approov.when(() -> Approov.initialize(context, "config-a", "auto", "reinit-bad"))
                    .thenThrow(new IllegalArgumentException("bad config"));

            IllegalArgumentException error = assertThrows(
                    IllegalArgumentException.class,
                    () -> ApproovService.initialize(context, "config-a", "reinit-bad"));

            assertEquals("bad config", error.getMessage());
            assertNull(ApproovService.getBaseHttpStack());
            assertFalse(ApproovTestSupport.getStaticField("isInitialized", Boolean.class));
            assertNull(ApproovTestSupport.getStaticField("configString", String.class));
        }
    }

    @Test
    public void fetchTokenReturnsTheSdkTokenOnSuccess() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult successResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "jwt-token",
                    "",
                    "trace-123",
                    false);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://example.com/reply"))
                    .thenReturn(successResult);

            assertEquals("jwt-token", ApproovService.fetchToken("https://example.com/reply"));
        }
    }

    @Test
    public void fetchTokenThrowsNetworkExceptionForNoNetwork() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult noNetworkResult =
                    ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.NO_NETWORK);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://example.com/reply"))
                    .thenReturn(noNetworkResult);

            ApproovNetworkException error = assertThrows(
                    ApproovNetworkException.class,
                    () -> ApproovService.fetchToken("https://example.com/reply"));

            assertEquals(Approov.TokenFetchStatus.NO_NETWORK, error.getTokenFetchStatus());
        }
    }

    @Test
    public void fetchSecureStringAllowsUnknownKeysAndReturnsNull() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult unknownKeyResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.UNKNOWN_KEY,
                    "",
                    null,
                    "",
                    false);
            approov.when(() -> Approov.fetchSecureStringAndWait("missing-key", null))
                    .thenReturn(unknownKeyResult);

            assertNull(ApproovService.fetchSecureString("missing-key", null));
        }
    }

    @Test
    public void accountMessageSignatureReturnsTheSdkValue() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getAccountMessageSignature("message"))
                    .thenReturn("base64-account-signature");

            assertEquals("base64-account-signature", ApproovService.getAccountMessageSignature("message"));
        }
    }

    @Test
    public void installMessageSignatureWrapsPlatformSigningFailures() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getInstallMessageSignature("message"))
                    .thenThrow(new IllegalStateException("private key unavailable"));

            ApproovException error = assertThrows(
                    ApproovException.class,
                    () -> ApproovService.getInstallMessageSignature("message"));

            assertTrue(error.getMessage().contains("private key unavailable"));
        }
    }

    @Test
    public void getApproovTokenHeaderValueOrStatusUsesConfiguredPrefixWithFallbackStatusWhenTokenMissing() {
        ApproovService.setApproovHeader("Approov-Token", "Bearer ");
        Approov.TokenFetchResult failureResult = ApproovTestSupport.tokenResult(
                Approov.TokenFetchStatus.MITM_DETECTED,
                "",
                "",
                "",
                false);
        Approov.TokenFetchResult emptySuccessResult = ApproovTestSupport.tokenResult(
                Approov.TokenFetchStatus.SUCCESS,
                "",
                "",
                "",
                false);

        assertEquals("Bearer MITM_DETECTED", ApproovService.getApproovTokenHeaderValueOrStatus(failureResult));
        assertEquals("Bearer SUCCESS", ApproovService.getApproovTokenHeaderValueOrStatus(emptySuccessResult));
    }

    @Test
    public void substituteHeaderReplacesPrefixedValueWithFetchedSecureString() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Api-Key", "Bearer header-secret");
            Approov.TokenFetchResult headerResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "",
                    "live-header",
                    "",
                    false);

            Approov.TokenFetchResult urlResult = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com"))
                    .thenReturn(urlResult);
            approov.when(() -> Approov.fetchSecureStringAndWait("header-secret", null))
                    .thenReturn(headerResult);

            ApproovService.substituteHeader("https://api.example.com", headers, "Api-Key", "Bearer ");

            assertEquals("Bearer live-header", headers.get("Api-Key"));
        }
    }

    @Test
    public void substituteQueryParamReplacesParamValueWithFetchedSecureString() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Map<String, String> params = new LinkedHashMap<>();
            params.put("secret", "query-secret");
            Approov.TokenFetchResult queryResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "",
                    "live-query",
                    "",
                    false);

            Approov.TokenFetchResult urlResult = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com"))
                    .thenReturn(urlResult);
            approov.when(() -> Approov.fetchSecureStringAndWait("query-secret", null))
                    .thenReturn(queryResult);

            ApproovService.substituteQueryParam("https://api.example.com", params, "secret");

            assertEquals("live-query", params.get("secret"));
        }
    }

    @Test
    public void substituteQueryParamInUrlStringReplacesEmbeddedQueryValue() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult queryResult = ApproovTestSupport.tokenResult(
                    Approov.TokenFetchStatus.SUCCESS,
                    "",
                    "live-query",
                    "",
                    false);
            Approov.TokenFetchResult urlResult = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.SUCCESS);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply?secret=query-secret"))
                    .thenReturn(urlResult);
            approov.when(() -> Approov.fetchSecureStringAndWait("query-secret", null))
                    .thenReturn(queryResult);

            String updatedUrl = ApproovService.substituteQueryParamInURLString(
                    "https://api.example.com/reply?secret=query-secret",
                    "secret");

            assertEquals("https://api.example.com/reply?secret=live-query", updatedUrl);
        }
    }
}
