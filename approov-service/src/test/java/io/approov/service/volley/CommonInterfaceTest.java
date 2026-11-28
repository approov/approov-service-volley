package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import android.content.Context;

import com.android.volley.toolbox.BaseHttpStack;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.LinkedHashMap;

/**
 * The method names shared by all Approov packages, the removed methods, the enabled flags, getLastARC
 * and the initialize contract.
 */
public class CommonInterfaceTest {
    private Context context;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        context = ApproovTestSupport.mockContext();
    }

    @After
    public void tearDown() {
        ApproovTestSupport.resetApproovServiceState();
    }

    private static Method method(String name, Class<?>... parameters) throws NoSuchMethodException {
        return ApproovService.class.getMethod(name, parameters);
    }

    private static boolean hasPublicMethod(String name) {
        for (Method method : ApproovService.class.getDeclaredMethods()) {
            if (method.getName().equals(name))
                return true;
        }
        return false;
    }

    // ---- names

    @Test
    public void theSharedNamesArePublicAndNotDeprecated() throws Exception {
        for (Method method : Arrays.asList(
                method("setTokenHeader", String.class, String.class),
                method("getTokenHeader"),
                method("getTokenPrefix"),
                method("setTraceIDHeader", String.class),
                method("getTraceIDHeader"),
                method("isApproovServiceEnabled"),
                method("isApproovProtectionEnabled"),
                method("setInstallAttributes", String.class),
                method("getLastARC"))) {
            assertTrue(method.getName(), Modifier.isPublic(method.getModifiers()));
            assertTrue(method.getName(), Modifier.isStatic(method.getModifiers()));
            assertFalse(method.getName(), method.isAnnotationPresent(Deprecated.class));
        }
    }

    @Test
    public void theOldNamesAreDeprecatedAliases() throws Exception {
        assertTrue(method("setApproovHeader", String.class, String.class).isAnnotationPresent(Deprecated.class));
        assertTrue(method("setApproovTraceIDHeader", String.class).isAnnotationPresent(Deprecated.class));
        assertTrue(method("getMessageSignature", String.class).isAnnotationPresent(Deprecated.class));
    }

    @Test
    public void theDeprecatedAliasesSetTheSameConfiguration() {
        ApproovService.setApproovHeader("X-Token", "Bearer ");
        assertEquals("X-Token", ApproovService.getTokenHeader());
        assertEquals("Bearer ", ApproovService.getTokenPrefix());
        ApproovService.setApproovHeader("X-Token", null);
        assertEquals("", ApproovService.getTokenPrefix());
        ApproovService.setApproovTraceIDHeader("X-Trace");
        assertEquals("X-Trace", ApproovService.getTraceIDHeader());
        ApproovService.setTraceIDHeader(null);
        assertNull(ApproovService.getTraceIDHeader());
    }

    @Test
    public void proceedOnNetworkFailAndPrefetchAreRemoved() {
        assertFalse(hasPublicMethod("setProceedOnNetworkFail"));
        assertFalse(hasPublicMethod("getProceedOnNetworkFail"));
        assertFalse(hasPublicMethod("prefetch"));
    }

    @Test
    public void setInstallAttributesBehavesAsSetInstallAttrsInToken() throws Exception {
        // before protection is enabled both throw the same way
        ApproovException shared = assertThrows(ApproovException.class, () -> ApproovService.setInstallAttributes("a.b.c"));
        assertTrue(shared.getMessage(), shared.getMessage().contains("not initialized"));
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            ApproovService.setInstallAttributes("a.b.c");
            approov.verify(() -> Approov.setInstallAttrsInToken("a.b.c"));
        }
    }

    // ---- enabled flags

    @Test
    public void theEnabledFlagsFollowInitialization() {
        assertFalse(ApproovService.isApproovServiceEnabled());
        assertFalse(ApproovService.isApproovProtectionEnabled());
        assertNotNull(ApproovService.getBaseHttpStack());

        ApproovService.initialize(context, "");
        assertTrue(ApproovService.isApproovServiceEnabled());
        assertFalse(ApproovService.isApproovProtectionEnabled());
        assertTrue(ApproovService.isInitialized());
        assertFalse(ApproovService.isApproovEnabled());

        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            assertTrue(ApproovService.isApproovServiceEnabled());
            assertTrue(ApproovService.isApproovProtectionEnabled());
            assertTrue(ApproovService.isApproovEnabled());
            assertNotNull(ApproovService.getBaseHttpStack());
        }
    }

    // ---- getLastARC

    private static Approov.TokenFetchResult withARC(String arc) {
        Approov.TokenFetchResult result = ApproovTestSupport.tokenResult(
                Approov.TokenFetchStatus.SUCCESS, "jwt", "", "", false);
        org.mockito.Mockito.when(result.getARC()).thenReturn(arc);
        return result;
    }

    @Test
    public void getLastARCMakesNoFetchAndIsEmptyBeforeAnyFetch() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            // pins for a host are present, which the old implementation fetched a token for
            approov.when(() -> Approov.getPins("public-key-sha256"))
                    .thenReturn(java.util.Collections.singletonMap("api.example.com",
                            java.util.Collections.singletonList("pin")));

            assertEquals("", ApproovService.getLastARC());

            approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), org.mockito.Mockito.never());
        }
    }

    @Test
    public void getLastARCReturnsTheARCOfTheLastFetchAndOnlyThat() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult first = withARC("ARC-ONE");
            Approov.TokenFetchResult second = withARC("ARC-TWO");
            Approov.TokenFetchResult none = withARC(null);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://one.example.com/")).thenReturn(first);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://two.example.com/")).thenReturn(second);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://none.example.com/")).thenReturn(none);

            ApproovService.fetchToken("https://one.example.com/");
            assertEquals("ARC-ONE", ApproovService.getLastARC());
            ApproovService.fetchToken("https://two.example.com/");
            assertEquals("ARC-TWO", ApproovService.getLastARC());
            // a fetch without an ARC clears the previous one
            ApproovService.fetchToken("https://none.example.com/");
            assertEquals("", ApproovService.getLastARC());

            approov.verify(() -> Approov.fetchApproovTokenAndWait(anyString()), org.mockito.Mockito.times(3));
        }
    }

    @Test
    public void aFetchThatThrowsLeavesNoARC() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult first = withARC("ARC-ONE");
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://one.example.com/")).thenReturn(first);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://bad.example.com/"))
                    .thenThrow(new IllegalStateException("not initialized"));
            ApproovService.fetchToken("https://one.example.com/");
            assertEquals("ARC-ONE", ApproovService.getLastARC());

            assertThrows(ApproovException.class, () -> ApproovService.fetchToken("https://bad.example.com/"));
            assertEquals("", ApproovService.getLastARC());
        }
    }

    @Test
    public void theARCOfARequestFetchIsRecordedAndInitializeClearsIt() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult result = withARC("ARC-REQ");
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://api.example.com/reply")).thenReturn(result);
            new ApproovHurlStack() {
                @Override
                protected com.android.volley.toolbox.HttpResponse executeNetworkRequest(
                        com.android.volley.Request<?> request, java.util.Map<String, String> headers) {
                    return org.mockito.Mockito.mock(com.android.volley.toolbox.HttpResponse.class);
                }
            }.executeRequest(ApproovTestSupport.request("https://api.example.com/reply"), new LinkedHashMap<>());
            assertEquals("ARC-REQ", ApproovService.getLastARC());

            ApproovService.initialize(context, "account-a");
            assertEquals("", ApproovService.getLastARC());
        }
    }

    // ---- initialize

    @Test
    public void aNullContextIsRejectedInEveryMode() {
        assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(null, ""));
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(null, "account-a"));
            approov.verifyNoInteractions();
        }
        assertFalse(ApproovService.isApproovServiceEnabled());
    }

    @Test
    public void aNullAccountIdIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApproovService.initialize(context, null));
        assertFalse(ApproovService.isApproovServiceEnabled());
    }

    @Test
    public void everyNonEmptyAccountIdAndCommentReachesTheSdkUnchanged() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenReturn(true);

            ApproovService.initialize(context, "account-a", "first comment");
            ApproovService.initialize(context, "account-b", null);
            ApproovService.initialize(context, "account-a", "other comment");

            approov.verify(() -> Approov.initialize(context, "account-a", "auto", "first comment"));
            approov.verify(() -> Approov.initialize(context, "account-b", "auto", null));
            approov.verify(() -> Approov.initialize(context, "account-a", "auto", "other comment"));
            assertTrue(ApproovService.isApproovProtectionEnabled());
        }
    }

    @Test
    public void theServiceLayerNeverComparesAccountIds() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            // the SDK accepts a different account ID, so the layer must too
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenReturn(false);
            ApproovService.initialize(context, "account-a");
            ApproovService.initialize(context, "account-b");
            assertTrue(ApproovService.isApproovProtectionEnabled());
            assertFalse(hasField("configString"));
        }
    }

    private static boolean hasField(String name) {
        for (java.lang.reflect.Field field : ApproovService.class.getDeclaredFields()) {
            if (field.getName().equals(name))
                return true;
        }
        return false;
    }

    @Test
    public void anSdkExceptionIsThrownUnchangedAndLeavesTheStateUntouched() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            BaseHttpStack before = ApproovService.getBaseHttpStack();
            IllegalStateException conflict = new IllegalStateException("config conflict");
            approov.when(() -> Approov.initialize(any(), anyString(), anyString(), any())).thenThrow(conflict);

            IllegalStateException thrown = org.junit.Assert.assertThrows(IllegalStateException.class,
                    () -> ApproovService.initialize(context, "account-b"));

            assertTrue(thrown == conflict);
            assertTrue(ApproovService.isApproovProtectionEnabled());
            assertEquals("X-Token", ApproovService.getTokenHeader());
            assertTrue(before == ApproovService.getBaseHttpStack());
        }
    }

    @Test
    public void anEmptyAccountIdNeverDowngradesActiveProtectionAndIsNotPassedToTheSdk() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            approov.clearInvocations();

            ApproovService.initialize(context, "");

            assertTrue(ApproovService.isApproovProtectionEnabled());
            // ignored, so the configuration is not reset either
            assertEquals("X-Token", ApproovService.getTokenHeader());
            approov.verifyNoInteractions();
        }
    }

    @Test
    public void eachInitializationThatIsNotIgnoredResetsTheConfiguration() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.setTokenHeader("X-Token", "Bearer ");
            ApproovService.setTraceIDHeader("X-Trace");
            ApproovService.setBindingHeader("Authorization");
            ApproovService.setUseApproovStatusIfNoToken(true);
            ApproovService.setServiceMutator(ApproovServiceMutator.ALWAYS_PROCEED);

            ApproovService.initialize(context, "account-a");

            assertEquals("Approov-Token", ApproovService.getTokenHeader());
            assertEquals("", ApproovService.getTokenPrefix());
            assertEquals("Approov-TraceID", ApproovService.getTraceIDHeader());
            assertNull(ApproovService.getBindingHeader());
            assertFalse(ApproovService.getUseApproovStatusIfNoToken());
            assertEquals(ApproovServiceMutator.DEFAULT, ApproovService.getServiceMutator());
        }
        // and the same for bypass mode
        ApproovTestSupport.resetApproovServiceState();
        ApproovService.initialize(context, "");
        ApproovService.setTokenHeader("X-Token", null);
        ApproovService.initialize(context, "");
        assertEquals("Approov-Token", ApproovService.getTokenHeader());
    }

    @Test
    public void theUserPropertyIsSetWhenProtectionIsFirstEnabled() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            approov.verify(() -> Approov.setUserProperty("approov-service-volley/" + BuildConfig.APPROOV_SERVICE_VERSION));
        }
    }
}
