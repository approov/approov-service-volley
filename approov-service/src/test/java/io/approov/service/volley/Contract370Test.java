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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mockStatic;

import android.content.Context;
import android.util.Log;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Contract checks of the public surface that need no request: the removed status header API, the exceptions the
 * mutator hooks declare, what initialize resets, an exclusion pattern that cannot be compiled, and the exact
 * exception messages of the direct methods.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class Contract370Test {
    private Context context;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        context = ApproovTestSupport.mockContext();
        ShadowLog.reset();
    }

    @After
    public void tearDown() {
        ApproovTestSupport.resetApproovServiceState();
        ShadowLog.reset();
    }

    private static boolean hasMethod(String name) {
        for (Method method : ApproovService.class.getDeclaredMethods()) {
            if (method.getName().equals(name))
                return true;
        }
        return false;
    }

    @Test
    public void theStatusHeaderApiDoesNotExist() {
        assertFalse(hasMethod("setStatusHeader"));
        assertFalse(hasMethod("getStatusHeader"));
        assertFalse(hasMethod("setProceedOnNetworkFail"));
        assertFalse(hasMethod("prefetch"));
    }

    // every hook of the mutator that is asked about a request or a result declares ApproovException, and the
    // pinning hook declares none
    @Test
    public void everyHookDeclaresApproovExceptionAndThePinningHookNone() {
        int hooks = 0;
        for (Method method : ApproovServiceMutator.class.getDeclaredMethods()) {
            if (!method.getName().startsWith("handle") || method.isSynthetic())
                continue;
            hooks++;
            boolean declares = false;
            for (Class<?> type : method.getExceptionTypes())
                declares |= (type == ApproovException.class);
            if (method.getName().equals("handlePinningShouldProcessRequest"))
                assertFalse("the pinning hook declares an exception", method.getExceptionTypes().length > 0);
            else
                assertTrue(method.getName() + " does not declare ApproovException", declares);
        }
        assertTrue("hooks found: " + hooks, hooks >= 11);
    }

    @Test
    public void theMessageSigningHookDeclaresApproovExceptionAndADelegatingOverrideCan() throws Exception {
        Method hook = ApproovDefaultMessageSigning.class.getMethod("handleRequestProcessedHeaders", Request.class,
                Map.class, ApproovRequestMutations.class);
        assertEquals(ApproovException.class, hook.getExceptionTypes()[0]);
        // an override that delegates to the standard decisions and declares it compiles and runs
        ApproovServiceMutator delegating = new ApproovServiceMutator() {
            @Override
            public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
                    ApproovRequestMutations changes) throws ApproovException {
                return ApproovServiceMutator.ALWAYS_PROCEED.handleRequestProcessedHeaders(request, headers, changes);
            }
        };
        assertNotNull(delegating.handleRequestProcessedHeaders(ApproovTestSupport.request("https://a.example/"),
                new java.util.LinkedHashMap<String, String>(), new ApproovRequestMutations()));
    }

    @Test
    public void theGettersOfTheSubstitutionsThrowBeforeInitialize() {
        IllegalStateException headers = assertThrows(IllegalStateException.class,
                ApproovService::getSubstitutionHeaders);
        assertEquals("ApproovService is not initialized", headers.getMessage());
        IllegalStateException queries = assertThrows(IllegalStateException.class,
                ApproovService::getSubstitutionQueryParams);
        assertEquals("ApproovService is not initialized", queries.getMessage());
    }

    @Test
    public void eachInitializationResetsTheSubstitutionsExclusionsAndSigning() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.addSubstitutionHeader("Api-Key", "Bearer ");
            ApproovService.addSubstitutionQueryParam("key");
            ApproovService.addExclusionURLRegex("/excluded");
            ApproovService.setServiceMutator(ApproovDefaultMessageSigning.combined());
            assertFalse(ApproovService.getSubstitutionHeaders().isEmpty());
            assertFalse(ApproovService.getSubstitutionQueryParams().isEmpty());
            assertFalse(ApproovService.getExclusionURLRegexs().isEmpty());

            ApproovService.initialize(context, "account-a");
            assertTrue(ApproovService.getSubstitutionHeaders().isEmpty());
            assertTrue(ApproovService.getSubstitutionQueryParams().isEmpty());
            assertTrue(ApproovService.getExclusionURLRegexs().isEmpty());
            assertEquals("signing is off", ApproovServiceMutator.DEFAULT, ApproovService.getServiceMutator());
        }
    }

    @Test
    public void anExclusionPatternThatCannotBeCompiledIsLoggedAndAddsNothing() throws Exception {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovService.initialize(context, "account-a");
            ApproovService.addExclusionURLRegex("/earlier");
            ApproovService.addExclusionURLRegex("([unclosed");
            assertEquals(java.util.Collections.singleton("/earlier"), ApproovService.getExclusionURLRegexs().keySet());
            boolean logged = false;
            for (ShadowLog.LogItem item : ShadowLog.getLogs())
                logged |= (item.type == Log.ERROR) && item.msg.startsWith("addExclusionURLRegex ([unclosed error");
            assertTrue("no error line", logged);
            // the earlier exclusion still matches
            Map<String, String> none = new java.util.LinkedHashMap<>();
            assertFalse(ApproovServiceMutator.DEFAULT.handleRequestShouldProcess(
                    ApproovTestSupport.request("https://a.example/earlier/x"), none));
            assertTrue(ApproovServiceMutator.DEFAULT.handleRequestShouldProcess(
                    ApproovTestSupport.request("https://a.example/other"), none));
        }
    }

    @Test
    public void theDirectMethodsFailBeforeInitializeWithTheirOwnName() {
        String[] methods = {"precheck", "getDeviceID", "fetchToken", "getAccountMessageSignature",
                "getInstallMessageSignature", "fetchSecureString", "fetchCustomJWT"};
        Class<?>[][] parameters = {{}, {}, {String.class}, {String.class}, {String.class},
                {String.class, String.class}, {String.class}};
        for (int i = 0; i < methods.length; i++) {
            final int n = i;
            Object[] args = new Object[parameters[n].length];
            for (int a = 0; a < args.length; a++)
                args[a] = "x";
            try {
                ApproovService.class.getMethod(methods[n], parameters[n]).invoke(null, args);
                throw new AssertionError(methods[n] + " did not throw");
            } catch (java.lang.reflect.InvocationTargetException e) {
                assertEquals(methods[n], ApproovException.class, e.getCause().getClass());
                assertEquals(methods[n] + ": SDK not initialized", e.getCause().getMessage());
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }
    }

    @Test
    public void anSdkExceptionIsWrappedWithItsClassAndMessage() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.fetchApproovTokenAndWait("https://example.com/a"))
                    .thenThrow(new IllegalStateException("sdk broke"));
            ApproovException error = assertThrows(ApproovException.class,
                    () -> ApproovService.fetchToken("https://example.com/a"));
            assertEquals("Wrapped java.lang.IllegalStateException: sdk broke", error.getMessage());
        }
    }

    @Test
    public void aMissingSignatureHasItsOwnMessage() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            approov.when(() -> Approov.getAccountMessageSignature("m")).thenReturn(null);
            approov.when(() -> Approov.getInstallMessageSignature("m")).thenReturn(null);
            assertEquals("no account signature available", assertThrows(ApproovException.class,
                    () -> ApproovService.getAccountMessageSignature("m")).getMessage());
            assertEquals("no device signature available", assertThrows(ApproovException.class,
                    () -> ApproovService.getInstallMessageSignature("m")).getMessage());
        }
    }

    @Test
    public void aRejectionNamesTheOperationTheStatusTheArcAndTheReasons() {
        try (MockedStatic<Approov> approov = mockStatic(Approov.class)) {
            ApproovTestSupport.initializeApproovService(approov);
            Approov.TokenFetchResult rejected = ApproovTestSupport.tokenResult(Approov.TokenFetchStatus.REJECTED);
            approov.when(() -> Approov.fetchSecureStringAndWait("precheck-dummy-key", null)).thenReturn(rejected);
            approov.when(() -> Approov.fetchSecureStringAndWait("the-key", null)).thenReturn(rejected);
            approov.when(() -> Approov.fetchCustomJWTAndWait("{}")).thenReturn(rejected);
            assertEquals("precheck: REJECTED: ARC123 hooked,rooted",
                    assertThrows(ApproovRejectionException.class, ApproovService::precheck).getMessage());
            assertEquals("fetchCustomJWT: REJECTED: ARC123 hooked,rooted", assertThrows(
                    ApproovRejectionException.class, () -> ApproovService.fetchCustomJWT("{}")).getMessage());
            assertEquals("fetchSecureString lookup for the-key: REJECTED: ARC123 hooked,rooted", assertThrows(
                    ApproovRejectionException.class, () -> ApproovService.fetchSecureString("the-key", null))
                    .getMessage());
        }
    }
}
